from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.session import FailedLoginAttempt
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.session import FailedAttemptCreate, FailedAttemptRead
from repositoryuta.services.crud_service import CrudService

# Solo lectura: FailedLoginAttempt se escribe internamente
# (session_repository.record_failed_attempt, llamado desde auth_service en
# cada intento fallido). Sin Delete a proposito — es evidencia de fuerza
# bruta, no debe poder borrarse desde ningun cliente (igual que
# FailedLoginsController.cs).
router = APIRouter(prefix="/api/failed-logins", tags=["failed-logins"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[FailedLoginAttempt, FailedAttemptCreate, FailedAttemptCreate]:
    return CrudService(session, FailedLoginAttempt)


@router.get("")
def list_failed_logins(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(FailedAttemptRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{attempt_id}")
def get_failed_login(
    attempt_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(attempt_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(FailedAttemptRead.model_validate(entity)))
