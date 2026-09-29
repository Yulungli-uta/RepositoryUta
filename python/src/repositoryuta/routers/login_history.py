from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import LoginHistory
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.audit import LoginHistoryCreate, LoginHistoryRead
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Solo lectura: LoginHistory se escribe internamente (AuthRepository via
# audit_repository.insert_login, llamado desde auth_service en cada intento de
# login) — ningun flujo legitimo pasa por este router. Sin PUT/DELETE, igual
# que LoginHistoryController.cs.
router = APIRouter(prefix="/api/login-history", tags=["login-history"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[LoginHistory, LoginHistoryCreate, LoginHistoryCreate]:
    return CrudService(session, LoginHistory)


@router.get("")
def list_login_history(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(LoginHistoryRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{login_id}")
def get_login_history(
    login_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(login_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(LoginHistoryRead.model_validate(entity)))
