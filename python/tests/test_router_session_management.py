from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.application import Application
from repositoryuta.models.session import UserSession
from repositoryuta.models.views import VwActiveApiClient, VwActiveSession


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_get_active_sessions_returns_camel_case_payload(client, sqlite_session) -> None:
    sqlite_session.add(
        VwActiveSession(
            session_id=uuid4(),
            user_id=uuid4(),
            email="juan@uta.edu.ec",
            user_type="Local",
            login_at=datetime(2026, 1, 1),
            expires_at=datetime(2026, 1, 2),
            status="Active",
            ws_is_active=False,
        )
    )
    sqlite_session.flush()

    response = client.get("/api/session-management/sessions", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()["data"][0]
    assert body["isWebSocketConnected"] is False
    assert body["email"] == "juan@uta.edu.ec"


def test_revoke_session_not_found_returns_404(client) -> None:
    response = client.post(
        f"/api/session-management/sessions/{uuid4()}/revoke", headers=_admin_header()
    )
    assert response.status_code == 404


def test_revoke_session_success(client, sqlite_session) -> None:
    session_row = UserSession(
        session_id=uuid4(),
        user_id=uuid4(),
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now() + timedelta(hours=1),
        is_active=True,
        status="Active",
    )
    sqlite_session.add(session_row)
    sqlite_session.flush()

    response = client.post(
        f"/api/session-management/sessions/{session_row.session_id}/revoke",
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["wasNotified"] is False


def test_revoke_all_user_sessions_returns_revoked_count(client, sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        UserSession(
            session_id=uuid4(),
            user_id=user_id,
            access_token="a",
            refresh_token="r",
            expires_at=datetime.now() + timedelta(hours=1),
            is_active=True,
            status="Active",
        )
    )
    sqlite_session.flush()

    response = client.post(
        f"/api/session-management/sessions/user/{user_id}/revoke-all", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["revokedCount"] == 1


def test_get_api_clients_returns_camel_case_payload(client, sqlite_session) -> None:
    sqlite_session.add(
        VwActiveApiClient(
            id=uuid4(),
            name="uta-signature",
            client_id="uta-signature",
            is_active=True,
            created_at=datetime.now(),
            calls_last_24h=3,
        )
    )
    sqlite_session.flush()

    response = client.get("/api/session-management/api-clients", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"][0]["callsLast24h"] == 3


def test_toggle_client_not_found_returns_404(client) -> None:
    response = client.post(
        f"/api/session-management/api-clients/{uuid4()}/toggle", headers=_admin_header()
    )
    assert response.status_code == 404


def test_toggle_client_suspends(client, sqlite_session) -> None:
    app = Application(
        name="uta-signature", client_id="uta-signature", client_secret_hash="h", is_active=True
    )
    sqlite_session.add(app)
    sqlite_session.flush()

    response = client.post(
        f"/api/session-management/api-clients/{app.id}/toggle", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["isActive"] is False


def test_rotate_secret_not_found_returns_404(client) -> None:
    response = client.post(
        f"/api/session-management/api-clients/{uuid4()}/rotate-secret", headers=_admin_header()
    )
    assert response.status_code == 404


def test_rotate_secret_returns_plaintext_once(client, sqlite_session) -> None:
    app = Application(name="uta-signature", client_id="uta-signature", client_secret_hash="old")
    sqlite_session.add(app)
    sqlite_session.flush()

    response = client.post(
        f"/api/session-management/api-clients/{app.id}/rotate-secret", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["newClientSecret"]


def test_endpoints_require_admin_role(client) -> None:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/session-management/sessions", headers=headers)

    assert response.status_code == 403
