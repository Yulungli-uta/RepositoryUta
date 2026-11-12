"""Mantenimiento periódico de sesiones y bitácora (espejo de SessionHousekeepingService .NET).

Marca como vencidas las sesiones cuyo ExpiresAt ya pasó (nada más las cerraba: solo cambiaban de
estado al renovarse, cerrar sesión o ser revocadas) y limpia la bitácora de eventos antigua.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.models.identity import UserActivityLog
from repositoryuta.models.session import UserSession

logger = logging.getLogger(__name__)

EXPIRE_BATCH_SIZE = 2000
MAX_BATCHES_PER_RUN = 20
PURGE_BATCH_SIZE = 5000
STARTUP_DELAY_SECONDS = 120
INTERVAL_SECONDS = 3600
MIN_RETENTION_DAYS = 30


def run_housekeeping_once(
    session: Session, *, retention_days: int = 90, now: datetime | None = None
) -> tuple[int, int]:
    """Devuelve (sesiones marcadas como vencidas, eventos de bitácora eliminados)."""
    now = now or clock.now()
    retention_days = max(MIN_RETENTION_DAYS, retention_days)

    expired = 0
    for _ in range(MAX_BATCHES_PER_RUN):
        ids = list(
            session.scalars(
                select(UserSession.session_id)
                .where(UserSession.is_active, UserSession.expires_at < now)
                .order_by(UserSession.expires_at)
                .limit(EXPIRE_BATCH_SIZE)
            )
        )
        if not ids:
            break
        result = session.execute(
            update(UserSession)
            .where(UserSession.session_id.in_(ids), UserSession.is_active)
            .values(is_active=False, status="Expired")
        )
        expired += result.rowcount
        session.commit()

    cutoff = now - timedelta(days=retention_days)
    purged = 0
    while True:
        ids = list(
            session.scalars(
                select(UserActivityLog.id)
                .where(UserActivityLog.timestamp < cutoff)
                .order_by(UserActivityLog.id)
                .limit(PURGE_BATCH_SIZE)
            )
        )
        if not ids:
            break
        result = session.execute(delete(UserActivityLog).where(UserActivityLog.id.in_(ids)))
        purged += result.rowcount
        session.commit()
        if len(ids) < PURGE_BATCH_SIZE:
            break

    return expired, purged


async def housekeeping_loop(session_factory: Callable[[], Session], *, retention_days: int) -> None:
    """Ciclo de fondo (se lanza desde el lifespan). Un error nunca detiene el ciclo."""
    await asyncio.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            await asyncio.to_thread(_run_with_new_session, session_factory, retention_days)
        except Exception:
            logger.exception("Falló el mantenimiento de sesiones; se reintenta luego")
        await asyncio.sleep(INTERVAL_SECONDS)


def _run_with_new_session(session_factory: Callable[[], Session], retention_days: int) -> None:
    session = session_factory()
    try:
        expired, purged = run_housekeeping_once(session, retention_days=retention_days)
        if expired or purged:
            logger.info(
                "Mantenimiento de sesiones: %s sesiones vencidas, %s eventos antiguos eliminados",
                expired,
                purged,
            )
    finally:
        session.close()
