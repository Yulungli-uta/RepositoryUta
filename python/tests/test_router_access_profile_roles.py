from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole
from repositoryuta.models.rbac import Role


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_get_by_profile_returns_all_without_pagination(client, sqlite_session) -> None:
    profile = AccessProfile(name="Perfil RH")
    roles = [Role(name=f"R_ROLE_{i}") for i in range(3)]
    sqlite_session.add_all([profile, *roles])
    sqlite_session.flush()
    sqlite_session.add_all(
        [AccessProfileRole(access_profile_id=profile.id, role_id=r.id) for r in roles]
    )
    sqlite_session.flush()

    response = client.get(
        f"/api/access-profile-roles/profile/{profile.id}", headers=_admin_header()
    )

    assert response.status_code == 200
    assert len(response.json()["data"]) == 3


def test_create_and_delete_access_profile_role(client, sqlite_session) -> None:
    profile = AccessProfile(name="Perfil RH")
    role = Role(name="R_RH")
    sqlite_session.add_all([profile, role])
    sqlite_session.flush()

    created = client.post(
        "/api/access-profile-roles",
        json={"accessProfileId": profile.id, "roleId": role.id},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    deleted = client.delete(
        f"/api/access-profile-roles/{profile.id}/{role.id}", headers=_admin_header()
    )
    assert deleted.status_code == 200


def test_delete_unknown_access_profile_role_returns_404(client) -> None:
    response = client.delete("/api/access-profile-roles/999/999", headers=_admin_header())
    assert response.status_code == 404
