"""Línea de tiempo de acceso de un usuario (espejo de UserAccessService .NET).

Une inicios de sesión, renovaciones, cierres, sesiones vencidas y eventos de seguimiento en un
solo listado ordenado por fecha, para dar seguimiento a reportes del tipo "no puede entrar".
"""

import math
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.models.audit import LoginHistory
from repositoryuta.models.identity import LocalUserCredential, User, UserActivityLog, UserEmployee
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.models.session import UserSession
from repositoryuta.schemas.user_access import (
    UserAccessEvent,
    UserAccessSummary,
    UserAccessTimeline,
)
from repositoryuta.services import activity_log_service as activity

MAX_RANGE_DAYS = 31
MAX_PER_SOURCE = 2000
MAX_PAGE_SIZE = 200

_ACTIVITY_TITLES = {
    activity.MENU_LOAD_EMPTY: "El menú del usuario salió vacío a pesar de tener roles",
    activity.MENU_LOAD_ERROR: "Error del servidor al cargar el menú",
    activity.REFRESH_REJECTED: "Renovación de sesión rechazada",
    activity.SESSION_RESET_AUTO: "Sesión cerrada automáticamente para renovar el acceso",
}


def get_timeline(
    session: Session,
    user_id: UUID,
    start: datetime,
    end: datetime,
    page: int,
    page_size: int,
) -> UserAccessTimeline | None:
    """None si el usuario no existe. El rango máximo es de 31 días."""
    user = session.get(User, user_id)
    if user is None:
        return None

    if end < start:
        start, end = end, start
    if (end - start).days > MAX_RANGE_DAYS:
        start = end - timedelta(days=MAX_RANGE_DAYS)
    page = max(page, 1)
    page_size = min(max(page_size, 1), MAX_PAGE_SIZE)

    events: list[UserAccessEvent] = []
    events.extend(_login_events(session, user_id, start, end))
    events.extend(_session_events(session, user_id, start, end))
    events.extend(_activity_events(session, user_id, start, end))

    events.sort(key=lambda e: e.timestamp, reverse=True)
    total = len(events)
    items = events[(page - 1) * page_size : page * page_size]
    total_pages = math.ceil(total / page_size) if page_size else 0

    return UserAccessTimeline(
        summary=_summary(session, user),
        items=items,
        page=page,
        page_size=page_size,
        total_count=total,
        total_pages=total_pages,
    )


def _summary(session: Session, user: User) -> UserAccessSummary:
    now = clock.now()

    roles = list(
        session.scalars(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == user.id,
                ~UserRole.is_deleted,
                ~Role.is_deleted,
                (UserRole.expires_at.is_(None)) | (UserRole.expires_at > now),
            )
        )
    )
    hr_employee_id = session.scalar(
        select(UserEmployee.hr_employee_id).where(
            UserEmployee.user_id == user.id, UserEmployee.is_active
        )
    )
    last_microsoft_login = session.scalar(
        select(func.max(LoginHistory.login_date_time)).where(
            LoginHistory.user_id == user.id,
            LoginHistory.login_type == "AzureAD",
            LoginHistory.login_status == "Success",
        )
    )
    # LastActivityAt nunca se llena: el último acceso real es la sesión más reciente
    # (inicio o renovación)
    last_app_access = session.scalar(
        select(func.max(UserSession.created_at)).where(UserSession.user_id == user.id)
    )
    valid_sessions = (
        session.scalar(
            select(func.count())
            .select_from(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.is_active,
                UserSession.expires_at > now,
            )
        )
        or 0
    )

    # Cuenta Local bloqueada: el bloqueo se mantiene hasta que un administrador lo desbloquea
    credential = session.get(LocalUserCredential, user.id)
    account_locked = False
    if credential is not None:
        until = credential.locked_until
        account_locked = bool(credential.is_locked or (until is not None and until > now))

    return UserAccessSummary(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        user_type=user.user_type,
        is_active=user.is_active,
        hr_employee_id=hr_employee_id,
        roles=roles,
        last_microsoft_login=last_microsoft_login,
        last_app_access=last_app_access,
        valid_sessions=valid_sessions,
        account_locked=bool(account_locked),
        locked_until=credential.locked_until if account_locked and credential else None,
    )


def _login_events(session: Session, user_id: UUID, start: datetime, end: datetime):
    rows = session.scalars(
        select(LoginHistory)
        .where(
            LoginHistory.user_id == user_id,
            LoginHistory.login_date_time >= start,
            LoginHistory.login_date_time <= end,
        )
        .order_by(LoginHistory.login_date_time.desc())
        .limit(MAX_PER_SOURCE)
    )
    for row in rows:
        device = describe_device(row.device_info, row.user_agent)
        common = {
            "timestamp": row.login_date_time,
            "ip_address": row.ip_address,
            "device": device,
            "session_id": row.session_id,
        }
        if row.login_type == "Refresh":
            yield UserAccessEvent(
                type="SECURITY",
                title="Reutilización de un token ya renovado",
                detail=row.failure_reason,
                **common,
            )
        elif row.login_status == "Success":
            title = (
                "Inicio de sesión con Microsoft"
                if row.login_type == "AzureAD"
                else "Inicio de sesión local"
            )
            yield UserAccessEvent(type="LOGIN", title=title, **common)
        else:
            detail = (
                row.login_status
                if not (row.failure_reason or "").strip()
                else f"{row.login_status}: {row.failure_reason}"
            )
            yield UserAccessEvent(
                type="LOGIN_FAILED",
                title="Intento de inicio de sesión fallido",
                detail=detail,
                **common,
            )


def _session_events(session: Session, user_id: UUID, start: datetime, end: datetime):
    # Se proyectan solo las columnas necesarias: la fila de sesión trae el access token completo
    rows = session.execute(
        select(
            UserSession.session_id,
            UserSession.status,
            UserSession.revoked_at,
            UserSession.revoked_by,
            UserSession.expires_at,
            UserSession.ip_address,
            UserSession.device_info,
            UserSession.user_agent,
        )
        .where(
            UserSession.user_id == user_id,
            (
                UserSession.revoked_at.is_not(None)
                & (UserSession.revoked_at >= start)
                & (UserSession.revoked_at <= end)
            )
            | (
                (UserSession.status == "Expired")
                & (UserSession.expires_at >= start)
                & (UserSession.expires_at <= end)
            ),
        )
        .limit(MAX_PER_SOURCE)
    )
    for row in rows:
        device = describe_device(row.device_info, row.user_agent)
        common = {"ip_address": row.ip_address, "device": device, "session_id": row.session_id}
        if row.status == "Rotated" and row.revoked_at is not None:
            yield UserAccessEvent(
                timestamp=row.revoked_at,
                type="SESSION_RENEWED",
                title="Sesión renovada",
                detail="El usuario seguía conectado; no inició sesión de nuevo",
                **common,
            )
        elif row.status == "Logout" and row.revoked_at is not None:
            yield UserAccessEvent(
                timestamp=row.revoked_at, type="LOGOUT", title="Cierre de sesión", **common
            )
        elif row.status == "Superseded":
            yield UserAccessEvent(
                timestamp=row.revoked_at or row.expires_at,
                type="SESSION_REVOKED",
                title="Sesión reemplazada",
                detail="Se cerró porque el usuario inició sesión de nuevo en el mismo navegador",
                **common,
            )
        elif row.status == "Expired":
            yield UserAccessEvent(
                timestamp=row.expires_at,
                type="SESSION_EXPIRED",
                title="Sesión vencida",
                detail="Venció sin que el usuario cerrara sesión",
                **common,
            )
        elif row.revoked_at is not None:
            by = (row.revoked_by or "").strip()
            detail = f"{row.status} por {by}" if by else row.status
            yield UserAccessEvent(
                timestamp=row.revoked_at,
                type="SESSION_REVOKED",
                title="Sesión revocada",
                detail=detail,
                **common,
            )


def _activity_events(session: Session, user_id: UUID, start: datetime, end: datetime):
    rows = session.scalars(
        select(UserActivityLog)
        .where(
            UserActivityLog.user_id == user_id,
            UserActivityLog.timestamp >= start,
            UserActivityLog.timestamp <= end,
        )
        .order_by(UserActivityLog.timestamp.desc())
        .limit(MAX_PER_SOURCE)
    )
    for row in rows:
        yield UserAccessEvent(
            timestamp=row.timestamp,
            type="ACTIVITY",
            title=_ACTIVITY_TITLES.get(row.activity, row.activity),
            detail=row.activity_details,
            ip_address=row.ip_address,
            device=describe_device(None, row.user_agent),
            session_id=row.session_id,
        )


def describe_device(device_info: str | None, user_agent: str | None) -> str | None:
    """Dispositivo legible ("Chrome · Android")."""
    ua = user_agent or ""
    if "Edg/" in ua:
        browser = "Edge"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Chrome/" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = None

    if "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = None

    if browser is None and os_name is None:
        return device_info.strip() if device_info and device_info.strip() else None
    return f"{browser} · {os_name}" if browser and os_name else (browser or os_name)
