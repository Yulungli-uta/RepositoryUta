from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.models.rbac import MenuItem, Role, RoleMenuItem, UserRole
from repositoryuta.repositories.menu_repository import MenuRepository


def test_get_menu_by_user_includes_parent_chain_even_if_not_directly_assigned(
    sqlite_session,
) -> None:
    user_id = uuid4()
    role = Role(name="R_RH")
    sqlite_session.add(role)
    sqlite_session.flush()

    parent = MenuItem(name="Recursos Humanos", order=1)
    sqlite_session.add(parent)
    sqlite_session.flush()

    child = MenuItem(name="Contratos", parent_id=parent.id, order=1)
    hidden_sibling = MenuItem(name="Reportes Internos", parent_id=parent.id, order=2)
    sqlite_session.add_all([child, hidden_sibling])
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserRole(user_id=user_id, role_id=role.id),
            # Solo "child" esta asignado directo al rol; "parent" debe aparecer
            # igual por la recursion de ParentId (fn_MenuByUser lo hace asi).
            RoleMenuItem(role_id=role.id, menu_item_id=child.id, is_visible=True),
        ]
    )
    sqlite_session.flush()

    menu = MenuRepository(sqlite_session).get_menu_by_user(user_id)
    names = {node.name for node in menu}

    assert names == {"Recursos Humanos", "Contratos"}
    assert "Reportes Internos" not in names


def test_get_menu_by_user_excludes_expired_role_assignment(sqlite_session) -> None:
    user_id = uuid4()
    role = Role(name="R_TEMPORAL")
    sqlite_session.add(role)
    sqlite_session.flush()

    item = MenuItem(name="Modulo Temporal", order=1)
    sqlite_session.add(item)
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserRole(
                user_id=user_id, role_id=role.id, expires_at=datetime.now() - timedelta(days=1)
            ),
            RoleMenuItem(role_id=role.id, menu_item_id=item.id),
        ]
    )
    sqlite_session.flush()

    menu = MenuRepository(sqlite_session).get_menu_by_user(user_id)

    assert menu == []
