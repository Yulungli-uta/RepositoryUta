from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.rbac import Role, UserRole


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_get_by_user_returns_no_profiles_when_none_assigned(client) -> None:
    response = client.get(f"/api/user-access-profiles/user/{uuid4()}", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"] == []


def test_assign_expands_profile_to_user_roles_and_logs_audit(client, sqlite_session) -> None:
    user_id = uuid4()
    profile = AccessProfile(name="Perfil RH")
    role = Role(name="R_RH")
    sqlite_session.add_all([profile, role])
    sqlite_session.flush()
    sqlite_session.add(AccessProfileRole(access_profile_id=profile.id, role_id=role.id))
    sqlite_session.flush()

    response = client.post(
        "/api/user-access-profiles",
        json={"userId": str(user_id), "accessProfileId": profile.id},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert sqlite_session.get(UserRole, (user_id, role.id)) is not None
    audit = sqlite_session.query(AuditLog).filter_by(action="AccessProfileAssigned").one()
    assert "admin@uta.edu.ec" in audit.new_values

    by_user = client.get(f"/api/user-access-profiles/user/{user_id}", headers=_admin_header())
    assert by_user.json()["data"][0]["name"] == "Perfil RH"


def test_unassign_removes_role_and_logs_audit(client, sqlite_session) -> None:
    user_id = uuid4()
    profile = AccessProfile(name="Perfil RH")
    role = Role(name="R_RH")
    sqlite_session.add_all([profile, role])
    sqlite_session.flush()
    sqlite_session.add(AccessProfileRole(access_profile_id=profile.id, role_id=role.id))
    sqlite_session.flush()
    client.post(
        "/api/user-access-profiles",
        json={"userId": str(user_id), "accessProfileId": profile.id},
        headers=_admin_header(),
    )

    response = client.delete(
        f"/api/user-access-profiles/{user_id}/{profile.id}", headers=_admin_header()
    )

    assert response.status_code == 200
    assert sqlite_session.get(UserRole, (user_id, role.id)) is None
    assert sqlite_session.query(AuditLog).filter_by(action="AccessProfileUnassigned").count() == 1
