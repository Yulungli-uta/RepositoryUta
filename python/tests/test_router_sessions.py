from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.session import UserSession


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_session(client, sqlite_session) -> None:
    session_row = UserSession(
        session_id=uuid4(),
        user_id=uuid4(),
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now() + timedelta(hours=1),
    )
    sqlite_session.add(session_row)
    sqlite_session.flush()

    listed = client.get("/api/sessions", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/sessions/{session_row.session_id}", headers=_admin_header())
    assert got.status_code == 200
    assert got.json()["data"]["accessToken"] == "a"


def test_get_unknown_session_returns_404(client) -> None:
    response = client.get(f"/api/sessions/{uuid4()}", headers=_admin_header())
    assert response.status_code == 404


def test_no_write_endpoints(client) -> None:
    assert client.post("/api/sessions", json={}, headers=_admin_header()).status_code == 405
    put_response = client.put(f"/api/sessions/{uuid4()}", json={}, headers=_admin_header())
    assert put_response.status_code == 405
    assert client.delete(f"/api/sessions/{uuid4()}", headers=_admin_header()).status_code == 405
