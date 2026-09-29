import base64
import json
from uuid import uuid4

import pytest

from repositoryuta.models.application import Application
from repositoryuta.models.audit import LoginHistory
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


def _make_app(session, *, client_id="uta-signature") -> Application:
    app = Application(
        name="uta-signature", client_id=client_id, client_secret_hash="h", is_active=True
    )
    session.add(app)
    session.flush()
    return app


def _patch_msal(monkeypatch: pytest.MonkeyPatch, token_result: dict | None = None) -> None:
    result = token_result or {"access_token": "tok"}
    monkeypatch.setattr(azure_auth_service, "_msal_app", lambda: _FakeMsalApp(result))


@pytest.fixture(autouse=True)
def _default_msal(monkeypatch: pytest.MonkeyPatch) -> None:
    """MSAL real hace un discovery HTTP en vivo del tenant al construir la app
    (incluso solo para build_auth_url) — se mockea por defecto en todos los
    tests de este archivo; los que necesitan un resultado de token distinto
    llaman a _patch_msal de nuevo con su propio payload."""
    _patch_msal(monkeypatch)


def _patch_graph_me(monkeypatch: pytest.MonkeyPatch, payload: dict) -> None:
    monkeypatch.setattr(
        azure_auth_service.requests, "get", lambda *a, **k: _FakeGraphResponse(payload)
    )


# ── build_auth_url ────────────────────────────────────────────────────────────


def test_build_auth_url_rejects_unknown_client(sqlite_session) -> None:
    with pytest.raises(PermissionError):
        azure_auth_service.build_auth_url(sqlite_session, "unknown")


def test_build_auth_url_success(sqlite_session) -> None:
    _make_app(sqlite_session)

    url, state = azure_auth_service.build_auth_url(
        sqlite_session, "uta-signature", browser_id="b1", code_challenge="cc1"
    )

    assert "login.microsoftonline.com" in url
    assert state


# ── handle_callback ───────────────────────────────────────────────────────────


def test_handle_callback_rejects_unknown_or_expired_state(sqlite_session) -> None:
    stale_state = base64.b64encode(
        json.dumps({"stateId": "never-issued", "clientId": "uta-signature"}).encode("utf-8")
    ).decode("ascii")

    with pytest.raises(PermissionError):
        azure_auth_service.handle_callback(sqlite_session, "code", stale_state)


def test_handle_callback_state_is_single_use(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "nadie@uta.edu.ec", "id": str(uuid4())})

    azure_auth_service.handle_callback(sqlite_session, "code", state)

    with pytest.raises(PermissionError):
        azure_auth_service.handle_callback(sqlite_session, "code", state)


def test_handle_callback_msal_failure_raises(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    _patch_msal(monkeypatch, {"error": "invalid_grant", "error_description": "bad code"})

    with pytest.raises(RuntimeError, match="bad code"):
        azure_auth_service.handle_callback(sqlite_session, "code", state)


def test_handle_callback_rejects_non_institutional_domain(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repositoryuta.config import get_settings

    _make_app(sqlite_session)
    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "juan@gmail.com", "id": str(uuid4())})
    monkeypatch.setattr(get_settings().azure_ad, "allowed_domain", "uta.edu.ec")

    with pytest.raises(PermissionError):
        azure_auth_service.handle_callback(sqlite_session, "code", state)


def test_handle_callback_unknown_local_user_returns_none(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "nadie@uta.edu.ec", "id": str(uuid4())})

    result = azure_auth_service.handle_callback(sqlite_session, "code", state)

    assert result is None


def test_handle_callback_success_creates_session_and_login_history(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    azure_object_id = str(uuid4())
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "juan@uta.edu.ec", "id": azure_object_id})

    result = azure_auth_service.handle_callback(sqlite_session, "code", state)

    assert result is not None
    assert result.access_token
    assert result.refresh_token
    sqlite_session.refresh(user)
    assert str(user.azure_object_id) == azure_object_id
    history = sqlite_session.query(LoginHistory).filter_by(login_type="AzureAD").one()
    assert history.login_status == "Success"


# ── complete_login_and_issue_delivery_code / exchange_delivery_code ─────────


def test_complete_login_returns_none_when_user_unknown(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    _, state = azure_auth_service.build_auth_url(
        sqlite_session, "uta-signature", code_challenge="cc"
    )
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "nadie@uta.edu.ec", "id": str(uuid4())})

    pair, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
        sqlite_session, "code", state
    )

    assert pair is None
    assert delivery_code is None


def test_complete_login_without_code_challenge_returns_pair_no_delivery_code(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()
    _, state = azure_auth_service.build_auth_url(sqlite_session, "uta-signature")
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "juan@uta.edu.ec", "id": str(uuid4())})

    pair, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
        sqlite_session, "code", state
    )

    assert pair is not None
    assert delivery_code is None


def test_exchange_delivery_code_full_flow(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    code_verifier = "a-secret-verifier"
    code_challenge = azure_auth_service._compute_code_challenge(code_verifier)
    _, state = azure_auth_service.build_auth_url(
        sqlite_session, "uta-signature", code_challenge=code_challenge
    )
    _patch_msal(monkeypatch, {"access_token": "tok"})
    _patch_graph_me(monkeypatch, {"userPrincipalName": "juan@uta.edu.ec", "id": str(uuid4())})

    pair, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
        sqlite_session, "code", state
    )
    assert pair is not None
    assert delivery_code is not None

    wrong = azure_auth_service.exchange_delivery_code(delivery_code, "wrong-verifier")
    assert wrong is None

    exchanged = azure_auth_service.exchange_delivery_code(delivery_code, code_verifier)
    assert exchanged is not None
    assert exchanged.access_token == pair.access_token

    # Un solo uso: el segundo intento con el verifier correcto ya no encuentra nada.
    reused = azure_auth_service.exchange_delivery_code(delivery_code, code_verifier)
    assert reused is None


def test_exchange_delivery_code_unknown_code_returns_none() -> None:
    assert azure_auth_service.exchange_delivery_code("unknown", "verifier") is None
