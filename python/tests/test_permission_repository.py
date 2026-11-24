from uuid import uuid4

from repositoryuta.models.views import VwRoleMenuItem, VwUserRole
from repositoryuta.repositories.permission_repository import PermissionRepository


def test_get_user_role_ids_and_roles(sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add_all(
        [
            VwUserRole(
                user_id=user_id,
                role_id=1,
                email="juan@uta.edu.ec",
                display_name="Juan",
                user_type="Local",
                role_name="R_EMPLOYEE",
            ),
            VwUserRole(
                user_id=user_id,
                role_id=2,
                email="juan@uta.edu.ec",
                display_name="Juan",
                user_type="Local",
                role_name="R_RH",
            ),
        ]
    )
    sqlite_session.flush()

    repo = PermissionRepository(sqlite_session)

    assert sorted(repo.get_user_role_ids(user_id)) == [1, 2]
    assert {r.role_name for r in repo.get_user_roles(user_id)} == {"R_EMPLOYEE", "R_RH"}


def test_get_user_menu_items_empty_when_user_has_no_roles(sqlite_session) -> None:
    assert PermissionRepository(sqlite_session).get_user_menu_items(uuid4()) == []


def test_get_user_menu_items_filters_by_role_ids(sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        VwUserRole(
            user_id=user_id,
            role_id=1,
            email="juan@uta.edu.ec",
            display_name="Juan",
            user_type="Local",
            role_name="R_EMPLOYEE",
        )
    )
    sqlite_session.add_all(
        [
            VwRoleMenuItem(
                role_id=1,
                menu_item_id=10,
                role_name="R_EMPLOYEE",
                menu_item_name="Mis Vacaciones",
                order=1,
                is_visible=True,
                role_specific_visibility=True,
            ),
            VwRoleMenuItem(
                role_id=99,
                menu_item_id=20,
                role_name="R_OTRO",
                menu_item_name="No deberia salir",
                order=1,
                is_visible=True,
                role_specific_visibility=True,
            ),
        ]
    )
    sqlite_session.flush()

    items = PermissionRepository(sqlite_session).get_user_menu_items(user_id)

    assert [i.menu_item_name for i in items] == ["Mis Vacaciones"]
