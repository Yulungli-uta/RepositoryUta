from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.views import VwRoleMenuItem, VwUserRole


class PermissionRepository:
    """Espejo de UserPermissionRepository (Data/Repositories/UserPermissionRepository.cs).

    Ambos metodos leen directo de las vistas dbo.vw_UserRoles / dbo.vw_RoleMenuItems
    (no de las tablas base) — igual que el .NET real, que resuelve todo del lado
    SQL en vez de recalcular la union en la aplicacion.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get_user_role_ids(self, user_id: UUID) -> list[int]:
        stmt = select(VwUserRole.role_id).where(VwUserRole.user_id == user_id).distinct()
        return list(self._session.scalars(stmt))

    def get_user_roles(self, user_id: UUID) -> list[VwUserRole]:
        stmt = select(VwUserRole).where(VwUserRole.user_id == user_id)
        return list(self._session.scalars(stmt))

    def get_user_menu_items(self, user_id: UUID) -> list[VwRoleMenuItem]:
        role_ids = self.get_user_role_ids(user_id)
        if not role_ids:
            return []

        stmt = select(VwRoleMenuItem).where(VwRoleMenuItem.role_id.in_(role_ids))
        return list(self._session.scalars(stmt))
