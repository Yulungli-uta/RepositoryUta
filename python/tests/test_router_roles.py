from uuid import uuid4

from fastapi.testclient import TestClient

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.main import create_app
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.rbac import Role


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def _employee_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def test_ping_is_public() -> None:
    with TestClient(create_app()) as anon_client:
        response = anon_client.get("/api/roles/ping")

    assert response.status_code == 200
    assert response.json() == "roles controller activo"


def test_list_roles_requires_admin_role(client) -> None:
    response = client.get("/api/roles", headers=_employee_header())

    assert response.status_code == 403


def test_list_roles_excludes_soft_deleted(client, sqlite_session) -> None:
    sqlite_session.add_all(
        [Role(name="R_RH", priority=50), Role(name="R_OBSOLETO", is_deleted=True)]
    )
    sqlite_session.flush()

    response = client.get("/api/roles", headers=_admin_header())

    assert response.status_code == 200
    names = [r["name"] for r in response.json()["data"]["items"]]
    assert names == ["R_RH"]


def test_create_role_returns_201_shape_and_logs_audit(client, sqlite_session) -> None:
    response = client.post(
        "/api/roles",
        json={"name": "R_NUEVO", "description": "desc", "priority": 10},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["name"] == "R_NUEVO"

    audit_rows = sqlite_session.query(AuditLog).filter_by(action="RoleCreated").all()
    assert len(audit_rows) == 1
    assert audit_rows[0].entity_id == str(body["id"])


def test_get_role_not_found(client) -> None:
    response = client.get("/api/roles/999999", headers=_admin_header())

    assert response.status_code == 404


def test_update_role_partial_does_not_clear_unset_fields(client, sqlite_session) -> None:
    role = Role(name="R_RH", description="original", priority=50)
    sqlite_session.add(role)
    sqlite_session.flush()

    response = client.put(
        f"/api/roles/{role.id}", json={"priority": 5}, headers=_admin_header()
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["priority"] == 5
    assert body["description"] == "original"


def test_update_unknown_role_returns_404(client) -> None:
    response = client.put(
        "/api/roles/999999", json={"priority": 1}, headers=_admin_header()
    )

    assert response.status_code == 404


def test_delete_unknown_role_returns_404(client) -> None:
    response = client.delete("/api/roles/999999", headers=_admin_header())

    assert response.status_code == 404


def test_delete_role_soft_deletes(client, sqlite_session) -> None:
    role = Role(name="R_TEMPORAL")
    sqlite_session.add(role)
    sqlite_session.flush()

    response = client.delete(f"/api/roles/{role.id}", headers=_admin_header())

    assert response.status_code == 200
    sqlite_session.expire(role)
    assert sqlite_session.get(Role, role.id).is_deleted is True
