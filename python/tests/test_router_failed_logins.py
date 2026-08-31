from datetime import datetime
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.session import FailedLoginAttempt


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_failed_logins(client, sqlite_session) -> None:
    sqlite_session.add(
        FailedLoginAttempt(
            user_email="juan@uta.edu.ec", attempted_at=datetime.now(), reason="BadPassword"
        )
    )
    sqlite_session.flush()

    response = client.get("/api/failed-logins", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["totalCount"] == 1
    assert body["items"][0]["userEmail"] == "juan@uta.edu.ec"


def test_get_unknown_failed_login_returns_404(client) -> None:
    response = client.get("/api/failed-logins/999", headers=_admin_header())
    assert response.status_code == 404


def test_no_write_endpoints(client) -> None:
    assert client.post("/api/failed-logins", json={}, headers=_admin_header()).status_code == 405
    assert client.delete("/api/failed-logins/1", headers=_admin_header()).status_code == 405
