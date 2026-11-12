from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.rbac import RoleMenuItem
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.rbac import RoleMenuItemCreate, RoleMenuItemRead, RoleMenuItemUpdate
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/role-menu-items", tags=["role-menu-items"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[RoleMenuItem, RoleMenuItemCreate, RoleMenuItemUpdate]:
    return CrudService(session, RoleMenuItem)


@router.get("/role/{role_id}")
def get_by_role(
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo de RoleMenuItemsController.GetByRole: TODAS las asignaciones del
    rol, sin paginacion — igual que el .NET."""
    stmt = select(RoleMenuItem).where(RoleMenuItem.role_id == role_id)
    items = list(session.scalars(stmt))
    return ApiResponse.ok(
        [dump(RoleMenuItemRead.model_validate(item)) for item in items]
    )


@router.get("")
def list_role_menu_items(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> dict:
    """Espejo EXACTO de RoleMenuItemsController.List: a diferencia de Roles y
    Permissions, esta respuesta NO va envuelta en ApiResponse — es una
    inconsistencia real del .NET, preservada tal cual."""
    result = _service(session).list(page, page_size)
    items = [dump(RoleMenuItemRead.model_validate(item)) for item in result.items]
    return {
        "items": items,
        "page": result.page,
        "pageSize": result.page_size,
        "totalCount": result.total_count,
        "totalPages": (result.total_count + result.page_size - 1) // result.page_size
        if result.page_size
        else 0,
        "hasPreviousPage": result.page > 1,
        "hasNextPage": result.page * result.page_size < result.total_count,
    }


@router.get("/{role_id}/{menu_item_id}")
def get_role_menu_item(
    role_id: int,
    menu_item_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(role_id, menu_item_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(RoleMenuItemRead.model_validate(entity)))


@router.post("")
def create_role_menu_item(
    dto: RoleMenuItemCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(RoleMenuItemRead.model_validate(result)))


@router.delete("/{role_id}/{menu_item_id}")
def delete_role_menu_item(
    role_id: int,
    menu_item_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(role_id, menu_item_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
