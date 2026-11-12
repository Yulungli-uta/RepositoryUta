"""Bitácora de eventos de acceso por usuario (auth.tbl_UserActivityLog).

Espejo de UserActivityService (.NET). Solo anomalías: la actividad normal (logins,
renovaciones, cierres) ya queda en LoginHistory y UserSessions.
"""

import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.models.identity import UserActivityLog

logger = logging.getLogger(__name__)

MENU_LOAD_EMPTY = "MENU_LOAD_EMPTY"
MENU_LOAD_ERROR = "MENU_LOAD_ERROR"
REFRESH_REJECTED = "REFRESH_REJECTED"
SESSION_RESET_AUTO = "SESSION_RESET_AUTO"

# Motivos que el cliente puede enviar al cerrar sesión (lista cerrada, sin texto libre).
ALLOWED_LOGOUT_REASONS = frozenset({"PERMISSIONS_RECOVERY"})

_AUTH_MODULE = "AUTH"
_CLIENT_EVENT_ACTION = "CLIENT_EVENT"


def _cut(value: str | None, max_length: int) -> str | None:
    return value if value is None or len(value) <= max_length else value[:max_length]


def log_activity(
    session: Session,
    user_id: UUID,
    activity: str,
    details: dict[str, Any] | None = None,
    *,
    session_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    commit: bool = False,
) -> None:
    """Registra un evento. Best-effort: nunca lanza ni altera la respuesta del llamador.

    El INSERT va en un savepoint para que un fallo de bitácora no invalide el resto de la
    transacción. `commit=True` es para los caminos que terminan en excepción HTTP: la
    dependencia get_db_session hace rollback ante cualquier excepción y el registro se perdería.
    """
    try:
        with session.begin_nested():
            session.add(
                UserActivityLog(
                    user_id=user_id,
                    session_id=session_id,
                    activity=_cut(activity, 100) or activity,
                    activity_details=json.dumps(details, ensure_ascii=False) if details else None,
                    ip_address=_cut(ip_address, 64),
                    user_agent=_cut(user_agent, 400),
                    timestamp=clock.now(),
                    module_accessed=_AUTH_MODULE,
                    action_performed=_CLIENT_EVENT_ACTION,
                )
            )
        if commit:
            session.commit()
    except Exception:
        logger.exception("No se pudo registrar el evento %s del usuario %s", activity, user_id)
