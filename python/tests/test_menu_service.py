from uuid import uuid4

from repositoryuta.models.rbac import MenuItem, Role, RoleMenuItem, UserRole
from repositoryuta.services.menu_service import get_menu_for_user


def test_get_menu_for_user_delegates_to_the_repository(sqlite_session) -> None:
    user_id = uuid4()
    role = Role(name="R_EMPLOYEE")
    sqlite_session.add(role)
    sqlite_session.flush()

    item = MenuItem(name="Mis Vacaciones", order=1)
    sqlite_session.add(item)
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserRole(user_id=user_id, role_id=role.id),
            RoleMenuItem(role_id=role.id, menu_item_id=item.id),
        ]
    )
    sqlite_session.flush()

    menu = get_menu_for_user(sqlite_session, user_id)

    assert [node.name for node in menu] == ["Mis Vacaciones"]
