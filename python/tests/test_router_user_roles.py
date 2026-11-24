from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.identity import User
from repositoryuta.models.rbac import Role, UserRole


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_create_user_role_logs_audit_with_actor_email(client, sqlite_session) -> None:
    user = User(id=uuid4(), email="juan@uta.edu.ec")
    role = Role(name="R_RH")
    sqlite_session.add_all([user, role])
    sqlite_session.flush()

    response = client.post(
        "/api/user-roles",
        json={"user_id": str(user.id), "role_id": role.id},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    audit = sqlite_session.query(AuditLog).filter_by(action="RoleAssigned").one()
    assert "AssignedBy=admin@uta.edu.ec" in audit.new_values


def test_create_duplicate_assignment_returns_409(client, sqlite_session) -> None:
    user = User(id=uuid4(), email="juan@uta.edu.ec")
    role = Role(name="R_RH")
    sqlite_session.add_all([user, role])
    sqlite_session.flush()
    sqlite_session.add(UserRole(user_id=user.id, role_id=role.id))
    sqlite_session.flush()

    response = client.post(
        "/api/user-roles",
        json={"user_id": str(user.id), "role_id": role.id},
        headers=_admin_header(),
    )

    assert response.status_code == 409


def test_get_update_delete_unknown_user_role_return_404(client) -> None:
    user_id = uuid4()

    assert client.get(f"/api/user-roles/{user_id}/1", headers=_admin_header()).status_code == 404
    assert (
        client.put(
            f"/api/user-roles/{user_id}/1", json={"reason": "x"}, headers=_admin_header()
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/api/user-roles/{user_id}/1", headers=_admin_header()).status_code == 404
    )


def test_list_is_not_wrapped_and_update_delete_work(client, sqlite_session) -> None:
    user = User(id=uuid4(), email="juan@uta.edu.ec")
    role = Role(name="R_RH")
    sqlite_session.add_all([user, role])
    sqlite_session.flush()
    sqlite_session.add(UserRole(user_id=user.id, role_id=role.id))
    sqlite_session.flush()

    listed = client.get("/api/user-roles", headers=_admin_header())
    assert listed.status_code == 200
    assert "success" not in listed.json()
    assert listed.json()["totalCount"] == 1

    updated = client.put(
        f"/api/user-roles/{user.id}/{role.id}",
        json={"reason": "renovacion"},
        headers=_admin_header(),
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["reason"] == "renovacion"

    deleted = client.delete(f"/api/user-roles/{user.id}/{role.id}", headers=_admin_header())
    assert deleted.status_code == 200

    missing = client.get(f"/api/user-roles/{user.id}/{role.id}", headers=_admin_header())
    assert missing.status_code == 404
