from uuid import UUID

from sqlalchemy.orm import Session

from repositoryuta.repositories.menu_repository import MenuRepository
from repositoryuta.schemas.rbac import MenuNode


def get_menu_for_user(session: Session, user_id: UUID) -> list[MenuNode]:
    """Espejo de MenuService.GetMenuForUserAsync: wrapper delgado sobre el
    repositorio, igual de simple que en .NET (no se le agrega logica que
    el original no tiene)."""
    return MenuRepository(session).get_menu_by_user(user_id)
