from pydantic import BaseModel, ConfigDict

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 20


class PagedRequest(BaseModel):
    """Espejo de PagedRequestDto.Normalize() (Models/DTOs/PagingDtos.cs).

    sort_direction no se restringe a "asc"/"desc" con un Literal a proposito:
    el .NET original solo hace ToLowerInvariant() sin validar el valor (cualquier
    otra cosa que no sea "desc" se trata como ascendente en los controllers que
    lo consumen) — restringirlo aqui rechazaria payloads que el .NET acepta hoy.
    """

    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE
    sort_by: str | None = None
    sort_direction: str = "asc"
    search: str | None = None

    def model_post_init(self, __context: object) -> None:
        self.page, self.page_size = clamp_page_params(self.page, self.page_size)
        self.sort_direction = (self.sort_direction or "asc").strip().lower()
        if self.sort_by is not None:
            self.sort_by = self.sort_by.strip() or None
        if self.search is not None:
            self.search = self.search.strip() or None


class PagedResult[T](BaseModel):
    """Espejo de PagedResult<T> (Data/Repositories/_Generic.cs) del .NET.

    `arbitrary_types_allowed`: `items` puede contener instancias ORM de
    SQLAlchemy crudas (igual que .NET, que pagina `TEntity` directo, no un DTO)
    cuando lo usa `services/crud_service.py`.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    items: list[T]
    page: int
    page_size: int
    total_count: int

    @classmethod
    def empty(cls, page: int, page_size: int) -> "PagedResult[T]":
        return cls(items=[], page=page, page_size=page_size, total_count=0)


def clamp_page_params(page: int, page_size: int) -> tuple[int, int]:
    """Misma normalización que GenericRepository<T>.GetPagedAsync: page>=1, 1<=page_size<=200."""
    page = max(page, 1)
    page_size = min(max(page_size, 1), MAX_PAGE_SIZE)
    return page, page_size
