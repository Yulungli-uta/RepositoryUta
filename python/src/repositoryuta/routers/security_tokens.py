from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import SecurityToken
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import (
    SecurityTokenCreate,
    SecurityTokenRead,
    SecurityTokenUpdate,
)
from repositoryuta.services.crud_service import CrudService

# Espejo de SecurityTokensController.cs: CRUD generico puro, sin auditoria propia.
router = APIRouter(prefix="/api/security-tokens", tags=["security-tokens"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[SecurityToken, SecurityTokenCreate, SecurityTokenUpdate]:
    return CrudService(session, SecurityToken)


@router.get("")
def list_security_tokens(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(SecurityTokenRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{token_id}")
def get_security_token(
    token_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(token_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SecurityTokenRead.model_validate(entity)))


@router.post("")
def create_security_token(
    dto: SecurityTokenCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(SecurityTokenRead.model_validate(result)))


@router.put("/{token_id}")
def update_security_token(
    token_id: UUID,
    dto: SecurityTokenUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    updated = _service(session).update(token_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SecurityTokenRead.model_validate(updated)))


@router.delete("/{token_id}")
def delete_security_token(
    token_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(token_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
