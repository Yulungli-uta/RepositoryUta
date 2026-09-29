from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.session import UserSession
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.session import UserSessionCreate, UserSessionRead, UserSessionUpdate
from repositoryuta.services.crud_service import CrudService

# Espejo de SessionsController.cs: solo lectura (List/Get) — UserSession se
# escribe internamente (AuthRepository.create_session, desde auth_service en
# login/refresh); la revocacion real vive en session_management.py
# (Administrador/R_DITIC). Igual que AuditLogController: consulta, no mutacion.
router = APIRouter(prefix="/api/sessions", tags=["sessions"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[UserSession, UserSessionCreate, UserSessionUpdate]:
    return CrudService(session, UserSession)


@router.get("")
def list_sessions(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(UserSessionRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{session_id}")
def get_session(
    session_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(session_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserSessionRead.model_validate(entity)))
