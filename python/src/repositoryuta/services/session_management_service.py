import base64
import secrets
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from repositoryuta.core.exceptions import NotFoundError
from repositoryuta.repositories.application_repository import ApplicationRepository
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.session_repository import SessionRepository
from repositoryuta.schemas.application import (
    ActiveApiClientRead,
    RotateSecretResult,
    ToggleClientResult,
)
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.session import ActiveSessionRead, RevokeSessionResult
from repositoryuta.services import token_service

# ── Sesiones de usuario ──────────────────────────────────────────────────────


def get_active_sessions(session: Session) -> list[ActiveSessionRead]:
    """Espejo de GetActiveSessionsAsync. IsWebSocketConnected siempre False
    aqui: el hub de SignalR esta fuera de alcance (regla de Fase 0 #13)."""
    rows = SessionRepository(session).get_active_sessions()
    return [
        ActiveSessionRead(
            session_id=row.session_id,
            user_id=row.user_id,
            email=row.email,
            display_name=row.display_name,
            user_type=row.user_type,
            ip_address=row.ip_address,
            user_agent=row.user_agent,
            browser_id=row.browser_id,
            login_at=row.login_at,
            last_activity_at=row.last_activity_at,
            expires_at=row.expires_at,
            status=row.status,
            is_websocket_connected=bool(row.ws_is_active),
            ws_last_ping=row.ws_last_ping,
        )
        for row in rows
    ]


def revoke_session(session: Session, session_id: UUID, revoked_by: str) -> RevokeSessionResult:
    """Espejo de RevokeSessionAsync. La notificacion ForceLogout vía SignalR
    queda fuera de alcance (regla de Fase 0 #13) — was_notified siempre False,
    con el mensaje que el .NET ya usa para ese caso."""
    sessions = SessionRepository(session)
    session_row = sessions.find_active_session_by_id(session_id)
    if session_row is None:
        raise NotFoundError(f"Sesión {session_id} no encontrada o ya inactiva.")

    user_id, ip_address, browser_id = (
        session_row.user_id,
        session_row.ip_address,
        session_row.browser_id,
    )
    sessions.revoke_session_by_admin(session_row, revoked_by)

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="SessionRevoked",
            module="Sessions",
            entity_id=str(session_id),
            old_values=f"UserId={user_id}; IpAddress={ip_address}; BrowserId={browser_id}",
            new_values=f"RevokedBy={revoked_by}; WsNotified=False",
        )
    )

    return RevokeSessionResult(
        session_id=session_id,
        was_notified=False,
        message="Sesión revocada. El usuario será desconectado en su próxima petición.",
    )


def revoke_all_user_sessions(session: Session, user_id: UUID, revoked_by: str) -> int:
    """Espejo de RevokeAllUserSessionsAsync."""
    sessions_repo = SessionRepository(session)
    revoked = sessions_repo.revoke_all_sessions_by_admin(user_id, revoked_by)
    if not revoked:
        return 0

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AllSessionsRevoked",
            module="Sessions",
            entity_id=str(user_id),
            new_values=f"RevokedCount={len(revoked)}; NotifiedCount=0; RevokedBy={revoked_by}",
        )
    )
    return len(revoked)


# ── Clientes API ─────────────────────────────────────────────────────────────


def get_active_api_clients(session: Session) -> list[ActiveApiClientRead]:
    rows = ApplicationRepository(session).get_active_api_clients()
    return [ActiveApiClientRead.model_validate(row) for row in rows]


def toggle_client(session: Session, application_id: UUID, changed_by: str) -> ToggleClientResult:
    """Espejo de ToggleClientAsync."""
    apps = ApplicationRepository(session)
    app = apps.find_not_deleted(application_id)
    if app is None:
        raise NotFoundError(f"Aplicación {application_id} no encontrada.")

    app.is_active = not app.is_active
    now = datetime.now()
    app.modified_at = now
    app.modified_by = changed_by

    if not app.is_active:
        app.suspended_at = now
        app.suspended_by = changed_by
    else:
        app.suspended_at = None
        app.suspended_by = None

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="ClientActivated" if app.is_active else "ClientSuspended",
            module="Applications",
            entity_id=str(application_id),
            new_values=(
                f"ClientId={app.client_id}; IsActive={app.is_active}; ChangedBy={changed_by}"
            ),
        )
    )

    return ToggleClientResult(
        application_id=application_id,
        client_id=app.client_id,
        is_active=app.is_active,
        message="Cliente API activado."
        if app.is_active
        else "Cliente API suspendido. Todos los tokens actuales serán rechazados.",
    )


def rotate_secret(session: Session, application_id: UUID, rotated_by: str) -> RotateSecretResult:
    """Espejo de RotateSecretAsync: 32 bytes aleatorios -> base64url sin
    padding (43 caracteres)."""
    apps = ApplicationRepository(session)
    app = apps.find_not_deleted(application_id)
    if app is None:
        raise NotFoundError(f"Aplicación {application_id} no encontrada.")

    new_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    now = datetime.now()

    app.client_secret_hash = token_service.hash_token(new_secret)
    app.secret_rotated_at = now
    app.secret_rotated_by = rotated_by
    app.modified_at = now
    app.modified_by = rotated_by

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="SecretRotated",
            module="Applications",
            entity_id=str(application_id),
            new_values=f"ClientId={app.client_id}; RotatedBy={rotated_by}; RotatedAt={now}",
        )
    )

    return RotateSecretResult(
        application_id=application_id,
        client_id=app.client_id,
        new_client_secret=new_secret,
        rotated_at=now,
    )
