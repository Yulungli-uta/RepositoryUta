from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import RoleChangeHistory


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_role_change_history(client, sqlite_session) -> None:
    entry = RoleChangeHistory(
        user_id=uuid4(), role_id=1, change_type="Assigned", changed_by="admin@uta.edu.ec"
    )
    sqlite_session.add(entry)
    sqlite_session.flush()

    listed = client.get("/api/role-change-history", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/role-change-history/{entry.id}", headers=_admin_header())
    assert got.status_code == 200
    assert got.json()["data"]["changeType"] == "Assigned"


def test_get_unknown_role_change_history_returns_404(client) -> None:
    response = client.get("/api/role-change-history/999", headers=_admin_header())
    assert response.status_code == 404


def test_no_write_endpoints(client) -> None:
    assert (
        client.post("/api/role-change-history", json={}, headers=_admin_header()).status_code
        == 405
    )
    assert client.delete("/api/role-change-history/1", headers=_admin_header()).status_code == 405
