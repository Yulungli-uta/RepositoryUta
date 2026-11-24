from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import PermissionChangeHistory
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import (
    PermissionChangeHistoryCreate,
    PermissionChangeHistoryRead,
    PermissionChangeHistoryUpdate,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Solo lectura: hoy ningun flujo del sistema escribe PermissionChangeHistory
# (tabla no alimentada por role_permissions.py/permissions.py) — catalogo de
# solo consulta, sin mutacion via API, igual que el .NET real.
router = APIRouter(prefix="/api/permission-change-history", tags=["permission-change-history"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[
    PermissionChangeHistory, PermissionChangeHistoryCreate, PermissionChangeHistoryUpdate
]:
    return CrudService(session, PermissionChangeHistory)


@router.get("")
def list_permission_change_history(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(PermissionChangeHistoryRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{history_id}")
def get_permission_change_history(
    history_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(history_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(PermissionChangeHistoryRead.model_validate(entity)))
