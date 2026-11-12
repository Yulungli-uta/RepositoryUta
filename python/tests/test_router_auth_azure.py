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
    # Categoria generica + referencia; nunca el motivo exacto (state invalido, cliente...)
    assert "expiró" in response.text
    assert "Código de referencia" in response.text
    assert "State inv" not in response.text


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


def test_azure_callback_without_code_returns_friendly_page_instead_of_422(client) -> None:
    # Microsoft redirige sin "code" y con "error" cuando el usuario pulsa "Atras" o cancela
    response = client.get(
        "/api/auth/azure/callback",
        params={"error": "access_denied", "error_description": "<script>alert(1)</script>"},
    )

    assert response.status_code == 200
    assert "no se completó el inicio de sesión" in response.text.lower()
    # No se refleja el error ni su descripcion en la pagina
    assert "access_denied" not in response.text
    assert "alert(1)" not in response.text


def test_azure_callback_without_code_notifies_relay_when_configured(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repositoryuta.config import get_settings

    monkeypatch.setenv("AZURE_AD__FRONTEND_RELAY_URL", "https://front.example/auth/azure/relay")
    get_settings.cache_clear()

    response = client.get(
        "/api/auth/azure/callback", params={"error": "access_denied"}, follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["location"] == (
        "https://front.example/auth/azure/relay?loginFailed=1&code=CANCELLED"
    )


def test_azure_callback_failure_redirects_to_relay_with_code_and_reference(
    client, sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64
    import json

    from repositoryuta.config import get_settings

    monkeypatch.setenv("AZURE_AD__FRONTEND_RELAY_URL", "https://front.example/auth/azure/relay")
    get_settings.cache_clear()
    state = base64.b64encode(
        json.dumps({"stateId": "x", "clientId": "unknown"}).encode("utf-8")
    ).decode("ascii")

    response = client.get(
        "/api/auth/azure/callback", params={"code": "c", "state": state}, follow_redirects=False
    )

    assert response.status_code == 302
    location = response.headers["location"]
    expected = "https://front.example/auth/azure/relay?loginFailed=1&code=EXPIRED_ATTEMPT&ref="
    assert location.startswith(expected)


def test_azure_claim_returns_delivery_code_only_for_matching_browser_and_challenge(
    client, sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()
    challenge = azure_auth_service._compute_code_challenge("verifier")
    _, state = azure_auth_service.build_auth_url(
        sqlite_session, "uta-signature", browser_id="browser-1", code_challenge=challenge
    )
    payload = {"userPrincipalName": "juan@uta.edu.ec", "id": str(uuid4())}
    monkeypatch.setattr(
        azure_auth_service.requests, "get", lambda *a, **k: _FakeGraphResponse(payload)
    )
    _, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
        sqlite_session, "code", state
    )

    ok = client.post(
        "/api/auth/azure/claim", json={"browserId": "browser-1", "codeChallenge": challenge}
    )
    assert ok.status_code == 200
    assert ok.json()["data"]["deliveryCode"] == delivery_code

    for body in (
        {"browserId": "browser-2", "codeChallenge": challenge},
        {"browserId": "browser-1", "codeChallenge": "otro"},
    ):
        other = client.post("/api/auth/azure/claim", json=body)
        assert other.status_code == 200
        assert other.json()["data"]["deliveryCode"] is None


def test_azure_claim_missing_fields_returns_400(client) -> None:
    response = client.post("/api/auth/azure/claim", json={"browserId": " ", "codeChallenge": "x"})
    assert response.status_code == 400
