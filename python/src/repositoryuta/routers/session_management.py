from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_email, get_db_session, require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import session_management_service as svc

router = APIRouter(prefix="/api/session-management", tags=["session-management"])

# Espejo de [Authorize(Roles = "Administrador,R_DITIC")] a nivel de clase en
# SessionManagementController.cs.
_ADMIN_ROLES = ("Administrador", "R_DITIC")


# ── Sesiones de usuario ──────────────────────────────────────────────────────


@router.get("/sessions")
def get_active_sessions(
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    sessions = svc.get_active_sessions(session)
    return ApiResponse.ok([dump(s) for s in sessions])


@router.post("/sessions/{session_id}/revoke")
def revoke_session(
    session_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    result = svc.revoke_session(session, session_id, actor_email)
    return ApiResponse.ok(dump(result))


@router.post("/sessions/user/{user_id}/revoke-all")
def revoke_all_user_sessions(
    user_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    count = svc.revoke_all_user_sessions(session, user_id, actor_email)
    return ApiResponse.ok({"revokedCount": count}, f"{count} sesión(es) revocada(s).")


# ── Clientes API ─────────────────────────────────────────────────────────────


@router.get("/api-clients")
def get_api_clients(
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    clients = svc.get_active_api_clients(session)
    return ApiResponse.ok([dump(c) for c in clients])


@router.post("/api-clients/{application_id}/toggle")
def toggle_client(
    application_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    result = svc.toggle_client(session, application_id, actor_email)
    return ApiResponse.ok(dump(result), result.message)


@router.post("/api-clients/{application_id}/rotate-secret")
def rotate_secret(
    application_id: UUID,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
    actor_email: str = Depends(get_current_user_email),
) -> ApiResponse:
    result = svc.rotate_secret(session, application_id, actor_email)
    return ApiResponse.ok(
        dump(result), "Secret rotado. Guarde el nuevo valor — no se volverá a mostrar."
    )
