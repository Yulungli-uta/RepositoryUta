from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from repositoryuta.core.rate_limit import get_client_ip
from repositoryuta.core.schema_base import dump
from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.routers.dependencies import (
    get_current_payload,
    get_current_user_id,
    get_db_session,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import activity_log_service
from repositoryuta.services.menu_service import get_menu_for_user

router = APIRouter(prefix="/api/menu", tags=["menu"])


@router.get("/user")
def get_menu(
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    payload: dict[str, Any] = Depends(get_current_payload),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """Espejo de MenuController.GetByUser. Además registra, para seguimiento, el menú vacío y los
    errores del servidor (anomalías que el navegador no puede reportar por sí mismo)."""
    sid = payload.get("sid")
    try:
        session_id = UUID(sid) if sid else None
    except ValueError:
        session_id = None
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("User-Agent")

    try:
        items = get_menu_for_user(session, user_id)
    except Exception as exc:
        session.rollback()
        activity_log_service.log_activity(
            session,
            user_id,
            activity_log_service.MENU_LOAD_ERROR,
            {"error": type(exc).__name__},
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            commit=True,
        )
        raise

    if not items:
        activity_log_service.log_activity(
            session,
            user_id,
            activity_log_service.MENU_LOAD_EMPTY,
            {"roles": jwt_core.roles_from_payload(payload)},
            session_id=session_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    return ApiResponse.ok([dump(item) for item in items])
