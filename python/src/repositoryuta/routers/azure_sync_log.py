from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import AzureSyncLog
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.audit import SyncLogCreate, SyncLogRead, SyncLogUpdate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Espejo de AzureSyncLogController.cs: pese al nombre, es solo una tabla de
# log de resultados de sincronizacion — CRUD normal, no llama a Azure. Sin
# Delete (igual que el .NET real): el historial de sincronizacion no se borra
# via API. [Authorize] simple, sin restriccion de rol.
router = APIRouter(prefix="/api/azure-sync-log", tags=["azure-sync-log"])


def _service(session: Session) -> CrudService[AzureSyncLog, SyncLogCreate, SyncLogUpdate]:
    return CrudService(session, AzureSyncLog)


@router.get("")
def list_azure_sync_log(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(SyncLogRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{log_id}")
def get_azure_sync_log(
    log_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    entity = _service(session).get(log_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SyncLogRead.model_validate(entity)))


@router.post("")
def create_azure_sync_log(
    dto: SyncLogCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(SyncLogRead.model_validate(result)))


@router.put("/{log_id}")
def update_azure_sync_log(
    log_id: int,
    dto: SyncLogUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    updated = _service(session).update(log_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SyncLogRead.model_validate(updated)))
