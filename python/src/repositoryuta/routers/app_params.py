from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.app_param import AppParam
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.app_param import AppParamCreate, AppParamRead, AppParamUpdate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Espejo de AppParamsController.cs: CRUD generico puro, sin auditoria propia
# (el .NET real tampoco la llama aqui) — PK es Nemonic (string), no un id
# autogenerado.
router = APIRouter(prefix="/api/app-params", tags=["app-params"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _service(session: Session) -> CrudService[AppParam, AppParamCreate, AppParamUpdate]:
    return CrudService(session, AppParam)


@router.get("")
def list_app_params(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(AppParamRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{nemonic}")
def get_app_param(
    nemonic: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    entity = _service(session).get(nemonic)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(AppParamRead.model_validate(entity)))


@router.post("")
def create_app_param(
    dto: AppParamCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(AppParamRead.model_validate(result)))


@router.put("/{nemonic}")
def update_app_param(
    nemonic: str,
    dto: AppParamUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    updated = _service(session).update(nemonic, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(AppParamRead.model_validate(updated)))


@router.delete("/{nemonic}")
def delete_app_param(
    nemonic: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    deleted = _service(session).delete(nemonic)
    if not deleted:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(message="Eliminado")
