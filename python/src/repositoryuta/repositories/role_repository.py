from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.rbac import Role


class RoleRepository:
    """Espejo de RoleRepository (Data/Repositories/_Specialized.cs).

    El filtro `is_deleted` es manual a proposito: Role implementa ISoftDeletable
    en .NET (filtro automatico alla via HasQueryFilter reflexivo); aqui se agrega
    explicito en cada lectura, sin ningun mecanismo "magico" global (regla de
    Fase 0 sobre soft-delete).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_active(self) -> list[Role]:
        stmt = select(Role).where(~Role.is_deleted).order_by(Role.priority, Role.name)
        return list(self._session.scalars(stmt))
