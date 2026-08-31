from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.rbac import Permission, Role, RolePermission
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.rbac import (
    RolePermissionCreate,
    RolePermissionRead,
    RolePermissionUpdate,
)
from repositoryuta.services.crud_service import CrudService

router = APIRouter(prefix="/api/role-permissions", tags=["role-permissions"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(
    session: Session,
) -> CrudService[RolePermission, RolePermissionCreate, RolePermissionUpdate]:
    return CrudService(session, RolePermission)


@router.get("/effective")
def get_effective_permissions(
    response: Response,
    roles: list[str] = Query(default=[]),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """Espejo de RolePermissionsController.GetEffectivePermissions:
    [AllowAnonymous] a proposito — es metadata de esquema RBAC (que puede
    hacer un rol), no datos de un usuario ni de una sesion, mismo criterio
    que /.well-known/jwks.json. Consumido por HrBackend para resolver
    autorizacion de accion sin flujo de login servicio-a-servicio.
    """
    response.headers["Cache-Control"] = "public, max-age=60"
    if not roles:
        return ApiResponse.ok([])

    stmt = (
        select(Permission.module, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .where(Role.name.in_(roles), Role.is_active, ~Role.is_deleted)
        .where(~Permission.is_deleted)
        .distinct()
    )
    codes = sorted({f"{module}.{action}".upper() for module, action in session.execute(stmt)})
    return ApiResponse.ok(codes)


@router.get("/role/{role_id}")
def get_by_role(
    role_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Espejo de RolePermissionsController.GetByRole: TODOS los permisos del
    rol, sin paginacion."""
    stmt = select(RolePermission).where(RolePermission.role_id == role_id)
    items = list(session.scalars(stmt))
    return ApiResponse.ok([dump(RolePermissionRead.model_validate(item)) for item in items])


@router.get("")
def list_role_permissions(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> dict:
    """Espejo EXACTO de RolePermissionsController.List: respuesta plana, sin
    envolver en ApiResponse."""
    result = _service(session).list(page, page_size)
    items = [dump(RolePermissionRead.model_validate(item)) for item in result.items]
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


@router.get("/{role_id}/{permission_id}")
def get_role_permission(
    role_id: int,
    permission_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(role_id, permission_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(RolePermissionRead.model_validate(entity)))


@router.post("")
def create_role_permission(
    dto: RolePermissionCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(RolePermissionRead.model_validate(result)))


@router.delete("/{role_id}/{permission_id}")
def delete_role_permission(
    role_id: int,
    permission_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(role_id, permission_id)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
