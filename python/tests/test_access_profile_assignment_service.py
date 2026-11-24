from uuid import uuid4

import pytest

from repositoryuta.core.exceptions import NotFoundError
from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole, UserAccessProfile
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.services import access_profile_assignment_service as svc


def _make_profile_with_roles(session, *names: str) -> tuple[AccessProfile, list[Role]]:
    profile = AccessProfile(name="Directora Administrativa")
    session.add(profile)
    session.flush()
    roles = [Role(name=n) for n in names]
    session.add_all(roles)
    session.flush()
    session.add_all(
        [AccessProfileRole(access_profile_id=profile.id, role_id=r.id) for r in roles]
    )
    session.flush()
    return profile, roles


def test_assign_unknown_profile_raises_not_found(sqlite_session) -> None:
    with pytest.raises(NotFoundError):
        svc.assign(sqlite_session, uuid4(), 999999, "admin@uta.edu.ec")


def test_assign_expands_profile_to_user_roles(sqlite_session) -> None:
    user_id = uuid4()
    profile, roles = _make_profile_with_roles(sqlite_session, "R_JEFE_INMEDIATO", "R_EMPLOYEE")

    svc.assign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    user_roles = sqlite_session.query(UserRole).filter_by(user_id=user_id).all()
    assert {ur.role_id for ur in user_roles} == {r.id for r in roles}
    assert all(ur.assigned_via == f"Profile:{profile.id}" for ur in user_roles)

    assignment = sqlite_session.get(UserAccessProfile, (user_id, profile.id))
    assert assignment is not None
    assert assignment.is_deleted is False


def test_assign_does_not_duplicate_already_held_role(sqlite_session) -> None:
    user_id = uuid4()
    profile, roles = _make_profile_with_roles(sqlite_session, "R_EMPLOYEE")
    # El usuario ya tiene el rol asignado directo, antes de asignar el perfil.
    sqlite_session.add(UserRole(user_id=user_id, role_id=roles[0].id, assigned_via="Direct"))
    sqlite_session.flush()

    svc.assign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    user_role = sqlite_session.get(UserRole, (user_id, roles[0].id))
    # No se sobreescribe el origen de una asignacion directa preexistente.
    assert user_role.assigned_via == "Direct"


def test_assign_reactivates_a_previously_unassigned_profile(sqlite_session) -> None:
    user_id = uuid4()
    profile, _roles = _make_profile_with_roles(sqlite_session, "R_EMPLOYEE")
    sqlite_session.add(
        UserAccessProfile(user_id=user_id, access_profile_id=profile.id, is_deleted=True)
    )
    sqlite_session.flush()

    svc.assign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    assignment = sqlite_session.get(UserAccessProfile, (user_id, profile.id))
    assert assignment.is_deleted is False


def test_get_assigned_profiles(sqlite_session) -> None:
    user_id = uuid4()
    profile, _roles = _make_profile_with_roles(sqlite_session, "R_EMPLOYEE")
    svc.assign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    profiles = svc.get_assigned_profiles(sqlite_session, user_id)

    assert [p.name for p in profiles] == ["Directora Administrativa"]


def test_unassign_removes_roles_owned_by_this_profile_only(sqlite_session) -> None:
    user_id = uuid4()
    profile, roles = _make_profile_with_roles(sqlite_session, "R_EMPLOYEE")
    svc.assign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    svc.unassign(sqlite_session, user_id, profile.id, "admin@uta.edu.ec")

    assert sqlite_session.get(UserRole, (user_id, roles[0].id)) is None
    assignment = sqlite_session.get(UserAccessProfile, (user_id, profile.id))
    assert assignment.is_deleted is True


def test_unassign_keeps_role_covered_by_another_active_profile(sqlite_session) -> None:
    user_id = uuid4()
    shared_role = Role(name="R_EMPLOYEE")
    sqlite_session.add(shared_role)
    sqlite_session.flush()

    profile_a = AccessProfile(name="Perfil A")
    profile_b = AccessProfile(name="Perfil B")
    sqlite_session.add_all([profile_a, profile_b])
    sqlite_session.flush()
    sqlite_session.add_all(
        [
            AccessProfileRole(access_profile_id=profile_a.id, role_id=shared_role.id),
            AccessProfileRole(access_profile_id=profile_b.id, role_id=shared_role.id),
        ]
    )
    sqlite_session.flush()

    svc.assign(sqlite_session, user_id, profile_a.id, "admin@uta.edu.ec")
    svc.assign(sqlite_session, user_id, profile_b.id, "admin@uta.edu.ec")

    svc.unassign(sqlite_session, user_id, profile_a.id, "admin@uta.edu.ec")

    # El rol sigue vivo porque el Perfil B (todavia activo) tambien lo otorga.
    assert sqlite_session.get(UserRole, (user_id, shared_role.id)) is not None


def test_unassign_unknown_assignment_is_a_no_op(sqlite_session) -> None:
    svc.unassign(sqlite_session, uuid4(), 999999, "admin@uta.edu.ec")
