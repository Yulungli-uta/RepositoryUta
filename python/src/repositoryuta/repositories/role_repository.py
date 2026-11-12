from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from repositoryuta.core.pagination import PagedResult, clamp_page_params
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

    def search_paged(self, search: str, page: int, page_size: int) -> PagedResult[Role]:
        """Roles no eliminados cuyo nombre o descripcion contienen TODAS las palabras de `search`
        (sin distinguir mayusculas; los comodines LIKE se escapan), paginados y ordenados por nombre (unico), igual que el .NET."""
        page, page_size = clamp_page_params(page, page_size)
        filters = [~Role.is_deleted]
        for term in search.split():
            filters.append(
                or_(
                    Role.name.icontains(term, autoescape=True),
                    Role.description.icontains(term, autoescape=True),
                )
            )

        total = self._session.scalar(select(func.count()).select_from(Role).where(*filters)) or 0
        if total == 0:
            return PagedResult.empty(page, page_size)

        stmt = (
            select(Role)
            .where(*filters)
            .order_by(Role.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return PagedResult(
            items=list(self._session.scalars(stmt)),
            page=page,
            page_size=page_size,
            total_count=total,
        )
