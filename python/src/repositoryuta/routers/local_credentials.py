from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import LocalUserCredential
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.routers.dependencies import (
    get_current_user_email,
    get_db_session,
    require_roles,
)
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import (
    LocalCredentialCreate,
    LocalCredentialRead,
    LocalCredentialUpdate,
)
from repositoryuta.services.crud_service import CrudService

# Espejo de LocalCredentialsController.cs: CRUD generico puro, sin auditoria
# propia. PK es UserId (relacion 1:1 con User).
router = APIRouter(prefix="/api/local-credentials", tags=["local-credentials"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[LocalUserCredential, LocalCredentialCreate, LocalCredentialUpdate]:
    return CrudService(session, LocalUserCredential)


@router.get("")
def list_local_credentials(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(LocalCredentialRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.post("/{user_id}/unlock")
def unlock_local_credential(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    """Desbloquea una cuenta Local: reinicia los intentos fallidos y levanta el bloqueo. Queda en la
    auditoria. Se usa este endpoint y no el PUT generico, que escribe los campos tal cual."""
    cred = session.get(LocalUserCredential, user_id)
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    now = clock.now()
    was_locked = bool(cred.is_locked or (cred.locked_until is not None and cred.locked_until > now))
    cred.failed_attempts = 0
    cred.is_locked = False
    cred.locked_until = None

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=user_id,
            action="AccountUnlocked",
            module="Authentication",
            entity_id=str(user_id),
            old_values="Locked" if was_locked else "NotLocked",
            new_values=f"UnlockedBy={actor_email}",
        )
    )
    return ApiResponse.ok({"unlocked": True, "wasLocked": was_locked})


@router.get("/{user_id}")
def get_local_credential(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(user_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(LocalCredentialRead.model_validate(entity)))


@router.post("")
def create_local_credential(
    dto: LocalCredentialCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(LocalCredentialRead.model_validate(result)))


@router.put("/{user_id}")
def update_local_credential(
    user_id: UUID,
    dto: LocalCredentialUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    updated = _service(session).update(user_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(LocalCredentialRead.model_validate(updated)))


@router.delete("/{user_id}")
def delete_local_credential(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(user_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
