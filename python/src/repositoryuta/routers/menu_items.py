from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.rbac import MenuItem
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.rbac import MenuItemCreate, MenuItemRead, MenuItemUpdate
from repositoryuta.services.crud_service import CrudService

# Espejo de MenuItemsController.cs: CRUD del catalogo de items de menu,
# distinto de routers/menu.py (que solo expone /api/menu/user, el menu ya
# resuelto para un usuario, de solo lectura).
router = APIRouter(prefix="/api/menu-items", tags=["menu-items"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[MenuItem, MenuItemCreate, MenuItemUpdate]:
    return CrudService(session, MenuItem)


@router.get("")
def list_menu_items(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> dict:
    """Espejo EXACTO de MenuItemsController.List: respuesta plana, sin
    envolver en ApiResponse (mismo patron que access-profiles/role-menu-items)."""
    result = _service(session).list(page, page_size)
    items = [dump(MenuItemRead.model_validate(item)) for item in result.items]
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


@router.get("/{menu_item_id}")
def get_menu_item(
    menu_item_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(menu_item_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(MenuItemRead.model_validate(entity)))


@router.post("")
def create_menu_item(
    dto: MenuItemCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(MenuItemRead.model_validate(result)))


@router.put("/{menu_item_id}")
def update_menu_item(
    menu_item_id: int,
    dto: MenuItemUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    updated = _service(session).update(menu_item_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(MenuItemRead.model_validate(updated)))


@router.delete("/{menu_item_id}")
def delete_menu_item(
    menu_item_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(menu_item_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
