from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import LocalUserCredential
from repositoryuta.routers.dependencies import get_db_session, require_roles
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
