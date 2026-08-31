from uuid import uuid4

import pytest

from repositoryuta.models.application import Application
from repositoryuta.models.identity import User
from repositoryuta.services import azure_auth_service


class _FakeMsalApp:
    def __init__(self, token_result: dict) -> None:
        self.token_result = token_result

    def get_authorization_request_url(self, scopes, state=None, redirect_uri=None):
        return f"https://login.microsoftonline.com/authorize?state={state}"

    def acquire_token_by_authorization_code(self, code, scopes=None, redirect_uri=None):
        return self.token_result


class _FakeGraphResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


@pytest.fixture(autouse=True)
def _default_msal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        azure_auth_service, "_msal_app", lambda: _FakeMsalApp({"access_token": "tok"})
    )


def _make_app(session, *, client_id="uta-signature") -> Application:
    app = Application(
        name="uta-signature", client_id=client_id, client_secret_hash="h", is_active=True
    )
    session.add(app)
    session.flush()
    return app


def test_azure_url_get_requires_known_client(client) -> None:
    response = client.get("/api/auth/azure/url", params={"clientId": "unknown"})
    assert response.status_code == 401


def test_azure_url_get_success(client, sqlite_session) -> None:
    _make_app(sqlite_session)

    response = client.get(
        "/api/auth/azure/url",
        params={"clientId": "uta-signature", "browserId": "b1", "codeChallenge": "cc"},
    )

    assert response.status_code == 200
    data = response.json()["data"]
    assert "login.microsoftonline.com" in data["url"]
    assert data["clientId"] == "uta-signature"


def test_azure_url_post_success(client, sqlite_session) -> None:
    _make_app(sqlite_session)

    response = client.post(
        "/api/auth/azure/url", json={"clientId": "uta-signature", "browserId": "b1"}
    )

    assert response.status_code == 200


def test_azure_callback_unauthorized_client_returns_closing_html(client, sqlite_session) -> None:
    import base64
    import json

    state = base64.b64encode(
        json.dumps({"stateId": "x", "clientId": "unknown"}).encode("utf-8")
    ).decode("ascii")

    response = client.get("/api/auth/azure/callback", params={"code": "c", "state": state})

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Acceso no autorizado" in response.text


def test_azure_callback_success_delivers_postmessage(
    client, sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    url_response = client.get(
        "/api/auth/azure/url",
        params={"clientId": "uta-signature", "codeChallenge": "test-challenge"},
    )
    state = url_response.json()["data"]["state"]

    monkeypatch.setattr(
        azure_auth_service.requests,
        "get",
        lambda *a, **k: _FakeGraphResponse(
            {"userPrincipalName": "juan@uta.edu.ec", "id": str(uuid4())}
        ),
    )

    response = client.get("/api/auth/azure/callback", params={"code": "c", "state": state})

    assert response.status_code == 200
    assert "window.opener.postMessage" in response.text
    assert "AZURE_LOGIN_DELIVERY" in response.text
    assert "deliveryCode" in response.text


def test_azure_exchange_unknown_code_returns_401(client) -> None:
    response = client.post(
        "/api/auth/azure/exchange", json={"deliveryCode": "unknown", "codeVerifier": "v"}
    )
    assert response.status_code == 401


def test_azure_exchange_missing_fields_returns_400(client) -> None:
    response = client.post(
        "/api/auth/azure/exchange", json={"deliveryCode": "", "codeVerifier": ""}
    )
    assert response.status_code == 400
