from uuid import uuid4

from repositoryuta.models.views import VwRoleMenuItem, VwUserRole
from repositoryuta.services import user_permission_service as svc


def test_get_user_roles(sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        VwUserRole(
            user_id=user_id,
            role_id=1,
            email="juan@uta.edu.ec",
            display_name="Juan",
            user_type="Local",
            role_name="R_RH",
        )
    )
    sqlite_session.flush()

    roles = svc.get_user_roles(sqlite_session, user_id)

    assert len(roles) == 1
    assert roles[0].role_name == "R_RH"


def test_get_user_menu_items_empty_when_no_roles(sqlite_session) -> None:
    assert svc.get_user_menu_items(sqlite_session, uuid4()) == []


def test_get_user_menu_items_and_permissions_urls_deduplicated_and_sorted(sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        VwUserRole(
            user_id=user_id,
            role_id=1,
            email="juan@uta.edu.ec",
            display_name="Juan",
            user_type="Local",
            role_name="R_RH",
        )
    )
    sqlite_session.add_all(
        [
            VwRoleMenuItem(
                role_id=1,
                menu_item_id=1,
                role_name="R_RH",
                menu_item_name="Empleados",
                url="/empleados",
                order=1,
                is_visible=True,
                role_specific_visibility=True,
            ),
            VwRoleMenuItem(
                role_id=1,
                menu_item_id=2,
                role_name="R_RH",
                menu_item_name="Reportes",
                url="/empleados",
                order=2,
                is_visible=True,
                role_specific_visibility=True,
            ),
            VwRoleMenuItem(
                role_id=1,
                menu_item_id=3,
                role_name="R_RH",
                menu_item_name="Sin URL",
                url=None,
                order=3,
                is_visible=True,
                role_specific_visibility=True,
            ),
        ]
    )
    sqlite_session.flush()

    menu_items = svc.get_user_menu_items(sqlite_session, user_id)
    assert len(menu_items) == 3

    urls = svc.get_user_permissions_urls(sqlite_session, user_id)
    assert urls == ["/empleados"]


def test_get_user_permissions_combines_roles_menu_and_urls(sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        VwUserRole(
            user_id=user_id,
            role_id=1,
            email="juan@uta.edu.ec",
            display_name="Juan",
            user_type="Local",
            role_name="R_RH",
        )
    )
    sqlite_session.add(
        VwRoleMenuItem(
            role_id=1,
            menu_item_id=1,
            role_name="R_RH",
            menu_item_name="Empleados",
            url="/empleados",
            order=1,
            is_visible=True,
            role_specific_visibility=True,
        )
    )
    sqlite_session.flush()

    result = svc.get_user_permissions(sqlite_session, user_id)

    assert len(result.roles) == 1
    assert result.permissions == ["/empleados"]
    assert len(result.menu_items) == 1
