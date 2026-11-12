"""Reloj central (estándar "Fecha y hora UTA").

Toda fecha/hora de negocio es hora de Ecuador (America/Guayaquil, UTC-5, sin horario de verano)
y la decide solo el servidor. Se devuelve un datetime naive (igual que un datetime2 de SQL Server).
La zona sale de TIME_ZONE_ID; no depende de la zona del servidor ni del contenedor.
"""

import os
from datetime import UTC, date, datetime
from zoneinfo import ZoneInfo

DEFAULT_ZONE_ID = "America/Guayaquil"


def _resolve_zone() -> ZoneInfo:
    return ZoneInfo(os.environ.get("TIME_ZONE_ID", "").strip() or DEFAULT_ZONE_ID)


ZONE = _resolve_zone()


def now() -> datetime:
    """Fecha y hora actual en Ecuador, sin tzinfo (para columnas datetime2)."""
    return datetime.now(ZONE).replace(tzinfo=None)


def today() -> date:
    """Día actual en Ecuador. Después de las 19:00 el día UTC ya es el siguiente."""
    return now().date()


def utc_now() -> datetime:
    """Instante actual en UTC con tzinfo. Solo para el borde con sistemas externos que lo exigen."""
    return datetime.now(UTC)
