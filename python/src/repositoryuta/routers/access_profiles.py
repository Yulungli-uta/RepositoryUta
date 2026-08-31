from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.access_profile import AccessProfile
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.access_profile import (
    AccessProfileCreate,
    AccessProfileRead,
    AccessProfileUpdate,
)
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/access-profiles", tags=["access-profiles"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[AccessProfile, AccessProfileCreate, AccessProfileUpdate]:
    return CrudService(session, AccessProfile)


@router.get("")
def list_access_profiles(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> dict:
    """Espejo EXACTO de AccessProfilesController.List: respuesta plana, sin
    envolver en ApiResponse (mismo patron que role-menu-items/user-roles)."""
    result = _service(session).list(page, page_size)
    items = [dump(AccessProfileRead.model_validate(item)) for item in result.items]
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


@router.get("/{profile_id}")
def get_access_profile(
    profile_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(profile_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(AccessProfileRead.model_validate(entity)))


@router.post("")
def create_access_profile(
    dto: AccessProfileCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AccessProfileCreated",
            module="AccessProfiles",
            entity_id=str(result.id),
            new_values=f"Name={result.name}; Description={result.description}",
        )
    )
    return ApiResponse.ok(dump(AccessProfileRead.model_validate(result)))


@router.put("/{profile_id}")
def update_access_profile(
    profile_id: int,
    dto: AccessProfileUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    updated = _service(session).update(profile_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AccessProfileUpdated",
            module="AccessProfiles",
            entity_id=str(profile_id),
            new_values=f"Description={dto.description}; IsActive={dto.is_active}",
        )
    )
    return ApiResponse.ok(dump(AccessProfileRead.model_validate(updated)))


@router.delete("/{profile_id}")
def delete_access_profile(
    profile_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Soft-delete manual (IsDeleted + IsActive en false): AccessProfile NO
    implementa ISoftDeletable en .NET, asi que el DELETE generico haria un
    borrado real — por eso este endpoint no usa CrudService.delete(), igual
    que el .NET real (que tampoco llama a ICrudService.DeleteAsync aqui)."""
    entity = session.get(AccessProfile, profile_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    entity.is_deleted = True
    entity.is_active = False
    session.flush()

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AccessProfileDeleted", module="AccessProfiles", entity_id=str(profile_id)
        )
    )
    return ApiResponse.ok(message="Eliminado")
