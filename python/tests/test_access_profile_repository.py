from uuid import uuid4

from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole
from repositoryuta.models.rbac import Role
from repositoryuta.repositories.access_profile_repository import AccessProfileRepository
from repositoryuta.schemas.access_profile import UserAccessProfileCreate


def test_list_active_excludes_soft_deleted(sqlite_session) -> None:
    sqlite_session.add_all(
        [
            AccessProfile(name="Directora Administrativa"),
            AccessProfile(name="Perfil Obsoleto", is_deleted=True),
        ]
    )
    sqlite_session.flush()

    profiles = AccessProfileRepository(sqlite_session).list_active()

    assert [p.name for p in profiles] == ["Directora Administrativa"]


def test_get_roles_for_profile_and_assignment_trace(sqlite_session) -> None:
    profile = AccessProfile(name="Directora Administrativa")
    role_jefe = Role(name="R_JEFE_INMEDIATO")
    role_empleado = Role(name="R_EMPLOYEE")
    sqlite_session.add_all([profile, role_jefe, role_empleado])
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            AccessProfileRole(access_profile_id=profile.id, role_id=role_jefe.id),
            AccessProfileRole(access_profile_id=profile.id, role_id=role_empleado.id),
        ]
    )
    sqlite_session.flush()

    repo = AccessProfileRepository(sqlite_session)
    roles = repo.get_roles_for_profile(profile.id)
    assert {r.name for r in roles} == {"R_JEFE_INMEDIATO", "R_EMPLOYEE"}

    user_id = uuid4()
    repo.record_assignment(
        UserAccessProfileCreate(user_id=user_id, access_profile_id=profile.id, assigned_by="admin")
    )
    sqlite_session.flush()

    profiles_for_user = repo.get_profiles_for_user(user_id)
    assert [p.name for p in profiles_for_user] == ["Directora Administrativa"]
