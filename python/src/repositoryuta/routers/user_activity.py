from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.models.identity import UserActivityLog
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import (
    UserActivityLogCreate,
    UserActivityLogRead,
    UserActivityLogUpdate,
)
from repositoryuta.services.crud_service import CrudService

# Espejo de UserActivityController.cs: [Authorize] simple, sin restriccion de
# rol (a diferencia de la mayoria de estos catalogos, que exigen
# Administrador/R_DITIC) — cualquier usuario autenticado puede llamarlo.
router = APIRouter(prefix="/api/user-activity", tags=["user-activity"])


def _service(
    session: Session,
) -> CrudService[UserActivityLog, UserActivityLogCreate, UserActivityLogUpdate]:
    return CrudService(session, UserActivityLog)


@router.get("")
def list_user_activity(
    page: int = 1,
    page_size: int = Query(default=20, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).list(page, page_size)
    items = [dump(UserActivityLogRead.model_validate(item)) for item in result.items]
    return ApiResponse.ok(
        {
            "items": items,
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.get("/{activity_id}")
def get_user_activity(
    activity_id: int,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    entity = _service(session).get(activity_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserActivityLogRead.model_validate(entity)))


@router.post("")
def create_user_activity(
    dto: UserActivityLogCreate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    result = _service(session).create(dto)
    return ApiResponse.ok(dump(UserActivityLogRead.model_validate(result)))


@router.put("/{activity_id}")
def update_user_activity(
    activity_id: int,
    dto: UserActivityLogUpdate,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(get_current_user_id),
) -> ApiResponse:
    updated = _service(session).update(activity_id, dto)
    if updated is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No existe")
    return ApiResponse.ok(dump(UserActivityLogRead.model_validate(updated)))
