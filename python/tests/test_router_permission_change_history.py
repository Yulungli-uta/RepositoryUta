from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import PermissionChangeHistory


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_permission_change_history(client, sqlite_session) -> None:
    entry = PermissionChangeHistory(
        role_id=1, permission_id=1, change_type="Added", changed_by="admin@uta.edu.ec"
    )
    sqlite_session.add(entry)
    sqlite_session.flush()

    listed = client.get("/api/permission-change-history", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/permission-change-history/{entry.id}", headers=_admin_header())
    assert got.status_code == 200
    assert got.json()["data"]["changeType"] == "Added"


def test_get_unknown_permission_change_history_returns_404(client) -> None:
    response = client.get("/api/permission-change-history/999", headers=_admin_header())
    assert response.status_code == 404


def test_no_write_endpoints(client) -> None:
    assert (
        client.post(
            "/api/permission-change-history", json={}, headers=_admin_header()
        ).status_code
        == 405
    )
    assert (
        client.delete("/api/permission-change-history/1", headers=_admin_header()).status_code
        == 405
    )
