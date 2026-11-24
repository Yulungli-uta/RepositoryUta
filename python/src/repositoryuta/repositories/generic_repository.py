from sqlalchemy import func, select
from sqlalchemy.orm import Session

from repositoryuta.core.pagination import PagedResult, clamp_page_params
from repositoryuta.models.base import SoftDeleteMixin


class GenericRepository[ModelT]:
    """Espejo de IGenericRepository<T>/GenericRepository<T>
    (Data/Repositories/_Generic.cs).

    El filtro de soft-delete no es un mecanismo global de SQLAlchemy: se aplica
    aqui a mano, solo si el modelo hereda de SoftDeleteMixin — espejo exacto
    del HasQueryFilter automatico que EF Core aplica UNICAMENTE a
    User/Role/Permission/MenuItem (regla ya establecida en Fase 0/3).
    """

    def __init__(self, session: Session, model: type[ModelT]) -> None:
        self._session = session
        self._model = model

    def _is_soft_deletable(self) -> bool:
        return issubclass(self._model, SoftDeleteMixin)

    def get_paged(self, page: int, page_size: int) -> PagedResult[ModelT]:
        page, page_size = clamp_page_params(page, page_size)

        count_stmt = select(func.count()).select_from(self._model)
        list_stmt = select(self._model)
        if self._is_soft_deletable():
            count_stmt = count_stmt.where(~self._model.is_deleted)
            list_stmt = list_stmt.where(~self._model.is_deleted)

        total = self._session.scalar(count_stmt) or 0
        if total == 0:
            return PagedResult.empty(page, page_size)

        # SQL Server exige ORDER BY junto a OFFSET/FETCH (SQLite lo tolera sin
        # eso, por eso los tests nunca lo detectaron). El .NET real tampoco pasa
        # un orderBy explicito aqui (CrudService.cs/UserRoleService.cs llaman
        # GetPagedAsync sin ordenar) pero no falla porque EF Core inyecta un
        # "ORDER BY (SELECT 1)" automatico al traducir Skip/Take sin OrderBy.
        # Ordenar por PK es mas determinístico que ese no-op y evita paginas
        # duplicadas/faltantes entre requests.
        list_stmt = list_stmt.order_by(*self._model.__mapper__.primary_key)
        list_stmt = list_stmt.offset((page - 1) * page_size).limit(page_size)
        items = list(self._session.scalars(list_stmt))
        return PagedResult(items=items, page=page, page_size=page_size, total_count=total)

    def get(self, *key: object) -> ModelT | None:
        entity = self._session.get(self._model, key if len(key) > 1 else key[0])
        if entity is None:
            return None
        if self._is_soft_deletable() and entity.is_deleted:
            return None
        return entity

    def add(self, entity: ModelT) -> ModelT:
        self._session.add(entity)
        self._session.flush()
        return entity

    def update(self, entity: ModelT) -> ModelT:
        self._session.flush()
        return entity

    def delete(self, *key: object) -> bool:
        """Espejo de GenericRepository<T>.DeleteAsync: soft-delete si el modelo
        implementa SoftDeleteMixin, borrado real si no (ej. RoleMenuItem,
        UserRole — tienen columna is_deleted en UserRole, pero el borrado
        generico de .NET no la usa, hace DELETE real igual)."""
        entity = self.get(*key)
        if entity is None:
            return False

        if isinstance(entity, SoftDeleteMixin):
            entity.is_deleted = True
        else:
            self._session.delete(entity)
        self._session.flush()
        return True
