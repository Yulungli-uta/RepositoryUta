import hashlib
import logging
import time

from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.repositories.app_param_repository import AppParamRepository

logger = logging.getLogger(__name__)

_ACCESS_TOKEN_LIFETIME_PARAM = "Jwt:AccessTokenLifetimeMinutes"
_CACHE_DURATION_SECONDS = 5 * 60


class _AccessTokenLifetimeCache:
    """Espejo del IMemoryCache de 5 min que usa JwtTokenService.cs para no
    pegarle a la BD en cada login/refresh."""

    def __init__(self) -> None:
        self._minutes: int | None = None
        self._cached_at: float = 0.0

    def get(self) -> int | None:
        if self._minutes is None:
            return None
        if (time.monotonic() - self._cached_at) >= _CACHE_DURATION_SECONDS:
            return None
        return self._minutes

    def set(self, minutes: int) -> None:
        self._minutes = minutes
        self._cached_at = time.monotonic()

    def clear(self) -> None:
        self._minutes = None
        self._cached_at = 0.0


_lifetime_cache = _AccessTokenLifetimeCache()


def reset_lifetime_cache() -> None:
    """Solo para pruebas — el cache real vive todo el ciclo de vida del proceso."""
    _lifetime_cache.clear()


def get_access_token_lifetime_minutes(session: Session) -> int:
    """Espejo de JwtTokenService.GetAccessTokenLifetimeAsync: lee
    auth.tbl_AppParams['Jwt:AccessTokenLifetimeMinutes'] con cache de 5 min; si
    la fila no existe, no es un entero valido, o la BD falla, cae a
    settings.jwt.access_token_lifetime_minutes (appsettings.json) — la emision
    de tokens nunca debe bloquearse por un problema de configuracion.
    """
    cached = _lifetime_cache.get()
    if cached is not None:
        return cached

    settings = get_settings()
    fallback = settings.jwt.access_token_lifetime_minutes
    lifetime = fallback

    try:
        raw = AppParamRepository(session).get_value(_ACCESS_TOKEN_LIFETIME_PARAM)
        if raw is not None:
            minutes = int(raw)
            if minutes > 0:
                lifetime = minutes
    except (ValueError, TypeError):
        logger.warning(
            "%s en auth.tbl_AppParams no es un entero valido, usando fallback de %s min",
            _ACCESS_TOKEN_LIFETIME_PARAM,
            fallback,
        )
    except Exception:
        logger.warning(
            "No se pudo leer %s de auth.tbl_AppParams, usando fallback de %s min",
            _ACCESS_TOKEN_LIFETIME_PARAM,
            fallback,
        )

    _lifetime_cache.set(lifetime)
    return lifetime


def hash_token(value: str) -> str:
    """Espejo de TokenService.Hash: SHA-256 hex en MAYUSCULAS (Convert.ToHexString
    de .NET produce hex uppercase) — usado para hashear el refresh token antes
    de guardarlo en UserSession.refresh_token. El casing importa: debe poder
    comparar contra hashes ya escritos por el .NET durante la convivencia.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()
