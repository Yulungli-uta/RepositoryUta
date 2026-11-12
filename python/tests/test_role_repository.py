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


def test_search_paged_filters_by_all_words_in_name_or_description_and_paginates(sqlite_session) -> None:
    sqlite_session.add_all(
        [
            Role(name="R_RRHH_ADMIN", description="Administrador de Talento Humano", priority=10),
            Role(name="R_RRHH_CONSULTA", description="Consulta de Talento Humano", priority=20),
            Role(name="R_GUARDIAS", description="Gestion de guardias", priority=30),
            Role(name="R_OBSOLETO_RRHH", description="Talento Humano", priority=1, is_deleted=True),
        ]
    )
    sqlite_session.flush()
    repo = RoleRepository(sqlite_session)

    by_name = repo.search_paged("rrhh", 1, 20)
    assert [r.name for r in by_name.items] == ["R_RRHH_ADMIN", "R_RRHH_CONSULTA"]
    assert by_name.total_count == 2

    by_words = repo.search_paged("talento admin", 1, 20)
    assert [r.name for r in by_words.items] == ["R_RRHH_ADMIN"]

    first_page = repo.search_paged("talento", 1, 1)
    assert [r.name for r in first_page.items] == ["R_RRHH_ADMIN"]
    assert first_page.total_count == 2
    assert [r.name for r in repo.search_paged("talento", 2, 1).items] == ["R_RRHH_CONSULTA"]

    assert repo.search_paged("%", 1, 20).total_count == 0
    assert repo.search_paged("no existe", 1, 20).items == []
