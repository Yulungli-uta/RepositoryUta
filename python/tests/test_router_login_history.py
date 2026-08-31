from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import LoginHistory


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_login_history(client, sqlite_session) -> None:
    sqlite_session.add(
        LoginHistory(user_id=uuid4(), login_type="Local", login_status="Success")
    )
    sqlite_session.flush()

    response = client.get("/api/login-history", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["totalCount"] == 1
    assert body["items"][0]["loginType"] == "Local"


def test_get_login_history(client, sqlite_session) -> None:
    entry = LoginHistory(user_id=uuid4(), login_type="Azure", login_status="Failed")
    sqlite_session.add(entry)
    sqlite_session.flush()

    response = client.get(f"/api/login-history/{entry.id}", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["loginStatus"] == "Failed"


def test_get_unknown_login_history_returns_404(client) -> None:
    response = client.get("/api/login-history/999", headers=_admin_header())
    assert response.status_code == 404


def test_no_write_endpoints(client) -> None:
    assert client.post("/api/login-history", json={}, headers=_admin_header()).status_code == 405
    assert client.delete("/api/login-history/1", headers=_admin_header()).status_code == 405
