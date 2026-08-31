from repositoryuta.models.rbac import Role
from repositoryuta.repositories.role_repository import RoleRepository


def test_list_active_excludes_soft_deleted_and_orders_by_priority_then_name(
    sqlite_session,
) -> None:
    sqlite_session.add_all(
        [
            Role(name="R_RH", priority=50),
            Role(name="R_EMPLOYEE", priority=100),
            Role(name="R_ADMIN", priority=50),
            Role(name="R_OBSOLETO", priority=1, is_deleted=True),
        ]
    )
    sqlite_session.flush()

    roles = RoleRepository(sqlite_session).list_active()

    assert [r.name for r in roles] == ["R_ADMIN", "R_RH", "R_EMPLOYEE"]
