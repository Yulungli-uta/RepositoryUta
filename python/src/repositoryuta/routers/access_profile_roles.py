from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.access_profile import AccessProfileRole
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.access_profile import (
    AccessProfileRoleCreate,
    AccessProfileRoleRead,
    AccessProfileRoleUpdate,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/access-profile-roles", tags=["access-profile-roles"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[AccessProfileRole, AccessProfileRoleCreate, AccessProfileRoleUpdate]:
    return CrudService(session, AccessProfileRole)


@router.get("/profile/{access_profile_id}")
def get_by_profile(
    access_profile_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo de AccessProfileRolesController.GetByProfile: TODOS los roles
    del perfil, sin paginacion."""
    stmt = select(AccessProfileRole).where(AccessProfileRole.access_profile_id == access_profile_id)
    items = list(session.scalars(stmt))
    return ApiResponse.ok([dump(AccessProfileRoleRead.model_validate(item)) for item in items])


@router.post("")
def create_access_profile_role(
    dto: AccessProfileRoleCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(AccessProfileRoleRead.model_validate(result)))


@router.delete("/{access_profile_id}/{role_id}")
def delete_access_profile_role(
    access_profile_id: int,
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(access_profile_id, role_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
