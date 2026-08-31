from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.rbac import UserRole
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.routers.dependencies import (
    get_current_user_email,
    get_db_session,
    require_roles,
)
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.rbac import UserRoleAssignmentRead, UserRoleCreate, UserRoleUpdate
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/user-roles", tags=["user-roles"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[UserRole, UserRoleCreate, UserRoleUpdate]:
    return CrudService(session, UserRole)


@router.get("")
def list_user_roles(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> dict:
    """Espejo EXACTO de UserRolesController.List: respuesta plana, sin
    envolver en ApiResponse (misma inconsistencia real que role-menu-items)."""
    result = _service(session).list(page, page_size)
    items = [
        dump(UserRoleAssignmentRead.model_validate(item))
        for item in result.items
    ]
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


@router.get("/{user_id}/{role_id}")
def get_user_role(
    user_id: UUID,
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(user_id, role_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserRoleAssignmentRead.model_validate(entity)))


@router.post("")
def create_user_role(
    dto: UserRoleCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    try:
        created = _service(session).create(dto)
    except IntegrityError as exc:
        # Espejo del catch(InvalidOperationException) del .NET: la asignacion
        # ya existe (violacion de la PK compuesta UserId+RoleId) -> 409, no 500.
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="El usuario ya tiene asignado ese rol"
        ) from exc

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=dto.user_id,
            action="RoleAssigned",
            module="UserRoles",
            entity_id=str(dto.role_id),
            new_values=(
                f"UserId={dto.user_id}; ExpiresAt={dto.expires_at}; "
                f"Reason={dto.reason}; AssignedBy={dto.assigned_by or actor_email}"
            ),
        )
    )
    return ApiResponse.ok(dump(UserRoleAssignmentRead.model_validate(created)))


@router.put("/{user_id}/{role_id}")
def update_user_role(
    user_id: UUID,
    role_id: int,
    dto: UserRoleUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    updated = _service(session).update((user_id, role_id), dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=user_id,
            action="RoleAssignmentUpdated",
            module="UserRoles",
            entity_id=str(role_id),
            new_values=(
                f"UserId={user_id}; ExpiresAt={dto.expires_at}; "
                f"Reason={dto.reason}; UpdatedBy={actor_email}"
            ),
        )
    )
    return ApiResponse.ok(dump(UserRoleAssignmentRead.model_validate(updated)))


@router.delete("/{user_id}/{role_id}")
def delete_user_role(
    user_id: UUID,
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    deleted = _service(session).delete(user_id, role_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")

    AuditRepository(session).log_action(
        AuditLogCreate(
            user_id=user_id,
            action="RoleUnassigned",
            module="UserRoles",
            entity_id=str(role_id),
            old_values=f"UserId={user_id}; RemovedBy={actor_email}",
        )
    )
    return ApiResponse.ok(message="Eliminado")
