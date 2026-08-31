from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import AuditLog


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_create_and_list_audit_log(client) -> None:
    created = client.post(
        "/api/audit-log",
        json={"action": "UserCreated", "module": "Users", "entityId": "1"},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    listed = client.get("/api/audit-log", headers=_admin_header())
    assert listed.status_code == 200
    body = listed.json()["data"]
    assert body["totalCount"] == 1
    assert body["items"][0]["action"] == "UserCreated"


def test_get_unknown_audit_log_returns_404(client) -> None:
    response = client.get("/api/audit-log/999", headers=_admin_header())
    assert response.status_code == 404


def test_get_by_module_filters_and_clamps_limit(client, sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add_all(
        [
            AuditLog(action="A", module="Users", entity_id="1", user_id=user_id),
            AuditLog(action="B", module="Users", entity_id="2", user_id=uuid4()),
            AuditLog(action="C", module="Roles", entity_id="3", user_id=user_id),
        ]
    )
    sqlite_session.flush()

    response = client.get(
        "/api/audit-log/by-module/Users",
        params={"userId": str(user_id), "limit": 0},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    items = response.json()["data"]
    assert len(items) == 1
    assert items[0]["action"] == "A"


def test_no_put_or_delete_endpoints(client) -> None:
    assert client.put("/api/audit-log/1", headers=_admin_header()).status_code == 405
    assert client.delete("/api/audit-log/1", headers=_admin_header()).status_code == 405
