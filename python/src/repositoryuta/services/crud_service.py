from pydantic import BaseModel
from sqlalchemy.orm import Session

from repositoryuta.core.pagination import PagedResult
from repositoryuta.repositories.generic_repository import GenericRepository


class CrudService[ModelT, CreateT: BaseModel, UpdateT: BaseModel]:
    """Espejo de CrudService<TEntity,TCreate,TUpdate> (Services/Implementations/CrudService.cs).

    Update usa `exclude_unset=True` (actualizacion parcial segura) en vez del
    comportamiento real de Mapster en .NET, que tambien copia los `null` de
    campos no enviados en el PUT — decision explicita aprobada por el usuario
    para no heredar ese riesgo de borrado accidental de datos en un PUT parcial.
    """

    def __init__(self, session: Session, model: type[ModelT]) -> None:
        self._repo: GenericRepository[ModelT] = GenericRepository(session, model)
        self._model = model

    def list(self, page: int, page_size: int) -> PagedResult[ModelT]:
        return self._repo.get_paged(page, page_size)

    def get(self, *key: object) -> ModelT | None:
        return self._repo.get(*key)

    def create(self, dto: CreateT) -> ModelT:
        entity = self._model(**dto.model_dump())
        return self._repo.add(entity)

    def update(self, key: object, dto: UpdateT) -> ModelT | None:
        keys = key if isinstance(key, tuple) else (key,)
        current = self._repo.get(*keys)
        if current is None:
            return None
        for field, value in dto.model_dump(exclude_unset=True).items():
            setattr(current, field, value)
        return self._repo.update(current)

    def delete(self, *key: object) -> bool:
        return self._repo.delete(*key)
