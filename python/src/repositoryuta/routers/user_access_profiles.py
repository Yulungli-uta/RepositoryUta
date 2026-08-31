from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.routers.dependencies import (
    get_current_user_email,
    get_db_session,
    require_roles,
)
from repositoryuta.schemas.access_profile import AccessProfileRead, UserAccessProfileCreate
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import access_profile_assignment_service as svc

router = APIRouter(prefix="/api/user-access-profiles", tags=["user-access-profiles"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


@router.get("/user/{user_id}")
def get_by_user(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Perfiles (activos) asignados actualmente a un usuario — solo
    informativo, no autoriza nada por si mismo."""
    profiles = svc.get_assigned_profiles(session, user_id)
    return ApiResponse.ok([dump(AccessProfileRead.model_validate(p)) for p in profiles])


@router.post("")
def assign(
    dto: UserAccessProfileCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    assigned_by = dto.assigned_by or actor_email
    svc.assign(session, dto.user_id, dto.access_profile_id, assigned_by)

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=dto.user_id,
            action="AccessProfileAssigned",
            module="UserAccessProfiles",
            entity_id=str(dto.access_profile_id),
            new_values=f"UserId={dto.user_id}; AssignedBy={assigned_by}",
        )
    )
    return ApiResponse.ok(message="Perfil asignado.")


@router.delete("/{user_id}/{access_profile_id}")
def unassign(
    user_id: UUID,
    access_profile_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    svc.unassign(session, user_id, access_profile_id, actor_email)

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=user_id,
            action="AccessProfileUnassigned",
            module="UserAccessProfiles",
            entity_id=str(access_profile_id),
            old_values=f"UserId={user_id}; RemovedBy={actor_email}",
        )
    )
    return ApiResponse.ok(message="Perfil removido.")
