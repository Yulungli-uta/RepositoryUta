from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import user_access_service

router = APIRouter(prefix="/api/user-access", tags=["user-access"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")
_DEFAULT_RANGE_DAYS = 7


@router.get("/{user_id}/timeline")
def get_timeline(
    user_id: UUID,
    date_from: datetime | None = Query(default=None, alias="from"),
    date_to: datetime | None = Query(default=None, alias="to"),
    page: int = 1,
    page_size: int = Query(default=50, alias="pageSize"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    """Línea de tiempo del usuario, de la más reciente a la más antigua (rango máximo 31 días)."""
    end = date_to or clock.now()
    start = date_from or end - timedelta(days=_DEFAULT_RANGE_DAYS)

    result = user_access_service.get_timeline(session, user_id, start, end, page, page_size)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return ApiResponse.ok(dump(result))
