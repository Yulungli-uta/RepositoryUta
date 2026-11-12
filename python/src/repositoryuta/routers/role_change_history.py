from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import RoleChangeHistory
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import (
    RoleChangeHistoryCreate,
    RoleChangeHistoryRead,
    RoleChangeHistoryUpdate,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Solo lectura: RoleChangeHistory se escribe internamente (UserRoleService, al
# asignar/reasignar/revocar un rol via user_roles.py) — este router nunca
# participa en esa escritura, igual que el .NET real.
router = APIRouter(prefix="/api/role-change-history", tags=["role-change-history"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[RoleChangeHistory, RoleChangeHistoryCreate, RoleChangeHistoryUpdate]:
    return CrudService(session, RoleChangeHistory)


@router.get("")
def list_role_change_history(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(RoleChangeHistoryRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{history_id}")
def get_role_change_history(
    history_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(history_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(RoleChangeHistoryRead.model_validate(entity)))
