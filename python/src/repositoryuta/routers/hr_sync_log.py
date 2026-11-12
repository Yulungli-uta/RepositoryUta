from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.audit import HRSyncLog
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.audit import SyncLogCreate, SyncLogRead, SyncLogUpdate
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services.crud_service import CrudService

# Espejo de HRSyncLogController.cs: igual que azure_sync_log.py, solo una
# tabla de log de sincronizacion con HR. Sin Delete. [Authorize] simple.
router = APIRouter(prefix="/api/hr-sync-log", tags=["hr-sync-log"])


def _service(session: Session) -> CrudService[HRSyncLog, SyncLogCreate, SyncLogUpdate]:
    return CrudService(session, HRSyncLog)


@router.get("")
def list_hr_sync_log(
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
def get_hr_sync_log(
    log_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    entity = _service(session).get(log_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SyncLogRead.model_validate(entity)))


@router.post("")
def create_hr_sync_log(
    dto: SyncLogCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(SyncLogRead.model_validate(result)))


@router.put("/{log_id}")
def update_hr_sync_log(
    log_id: int,
    dto: SyncLogUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    updated = _service(session).update(log_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(SyncLogRead.model_validate(updated)))
