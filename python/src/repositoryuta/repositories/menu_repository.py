from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from repositoryuta.models.rbac import MenuItem, RoleMenuItem, UserRole
from repositoryuta.schemas.rbac import MenuNode


class MenuRepository:
    """Espejo de MenuRepository.GetMenuByUserAsync, que en .NET delega en
    auth.fn_MenuByUser (Database/auth/05_functions.sql): CTE recursiva — menu
    directo por rol, mas toda la cadena de padres aunque el padre no este
    asignado directo al rol.

    Se replica aqui con una CTE recursiva de SQLAlchemy en vez de invocar la
    funcion SQL, porque ya se leyo el cuerpo completo y es portable con
    confianza razonable (regla de Fase 0 #11) — pero preservando los mismos 4
    filtros exactos y la misma recursion por ParentId.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_menu_by_user(self, user_id: UUID) -> list[MenuNode]:
        now = datetime.now()

        base_query = (
            select(
                MenuItem.id.label("id"),
                MenuItem.parent_id.label("parent_id"),
                MenuItem.name.label("name"),
                MenuItem.url.label("url"),
                MenuItem.icon.label("icon"),
                MenuItem.order.label("order"),
            )
            .join(RoleMenuItem, RoleMenuItem.menu_item_id == MenuItem.id)
            .join(UserRole, UserRole.role_id == RoleMenuItem.role_id)
            .where(
                UserRole.user_id == user_id,
                ~UserRole.is_deleted,
                (UserRole.expires_at.is_(None)) | (UserRole.expires_at > now),
                RoleMenuItem.is_visible,
                ~MenuItem.is_deleted,
                MenuItem.is_visible,
            )
            .distinct()
        )

        menu_cte = base_query.cte(name="menu_cte", recursive=True)

        parent = aliased(MenuItem)
        recursive_query = (
            select(
                parent.id.label("id"),
                parent.parent_id.label("parent_id"),
                parent.name.label("name"),
                parent.url.label("url"),
                parent.icon.label("icon"),
                parent.order.label("order"),
            )
            .join(menu_cte, parent.id == menu_cte.c.parent_id)
            .where(~parent.is_deleted, parent.is_visible)
        )
        menu_cte = menu_cte.union_all(recursive_query)

        rows = self._session.execute(select(menu_cte).distinct()).all()
        return [MenuNode.model_validate(row, from_attributes=True) for row in rows]
