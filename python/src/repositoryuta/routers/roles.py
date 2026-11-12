import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump, dump_json
from repositoryuta.models.rbac import Role
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.role_repository import RoleRepository
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.rbac import RoleCreate, RoleRead, RoleUpdate
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/roles", tags=["roles"])

# Espejo de [Authorize(Roles = "Administrador,R_DITIC")] a nivel de clase en
# RolesController.cs.
_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[Role, RoleCreate, RoleUpdate]:
    return CrudService(session, Role)


@router.get("/ping")
def ping() -> str:
    """Espejo de RolesController.Ping — [AllowAnonymous], sin logica real."""
    return "roles controller activo"


@router.get("")
def list_roles(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    search: str | None = None,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    # `search` es un agregado respecto al .NET (que solo pagina): filtra por nombre/descripcion en el servidor
    # y mantiene la paginacion. Sin `search` el comportamiento es el de siempre.
    if search and search.strip():
        result = RoleRepository(session).search_paged(search.strip(), page, page_size)
    else:
        result = _service(session).list(page, page_size)
    items = [dump(RoleRead.model_validate(item)) for item in result.items]
    total_pages = math.ceil(result.total_count / result.page_size) if result.page_size > 0 else 0
    # totalPages / hasPreviousPage / hasNextPage: los devuelve PagedResult<T> del .NET y los usan los paginadores de HrFrontend.
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
            "totalPages": total_pages,
            "hasPreviousPage": result.page > 1,
            "hasNextPage": result.page < total_pages,
        }
    )


@router.get("/{role_id}")
def get_role(
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(role_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(RoleRead.model_validate(entity)))


@router.post("")
def create_role(
    dto: RoleCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    read = RoleRead.model_validate(result)
    AuditRepository(session).log_action(
        AuditLogCreate(
            action="RoleCreated",
            module="Roles",
            entity_id=str(result.id),
            new_values=dump_json(read),
        )
    )
    return ApiResponse.ok(dump(read))


@router.put("/{role_id}")
def update_role(
    role_id: int,
    dto: RoleUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    service = _service(session)
    before = service.get(role_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    before_snapshot = dump_json(RoleRead.model_validate(before))

    updated = service.update(role_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    read = RoleRead.model_validate(updated)
    AuditRepository(session).log_action(
        AuditLogCreate(
            action="RoleUpdated",
            module="Roles",
            entity_id=str(role_id),
            old_values=before_snapshot,
            new_values=dump_json(read),
        )
    )
    return ApiResponse.ok(dump(read))


@router.delete("/{role_id}")
def delete_role(
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    service = _service(session)
    before = service.get(role_id)
    if before is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    before_snapshot = dump_json(RoleRead.model_validate(before))

    deleted = service.delete(role_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="RoleDeleted", module="Roles", entity_id=str(role_id), old_values=before_snapshot
        )
    )
    return ApiResponse.ok(message="Eliminado")
