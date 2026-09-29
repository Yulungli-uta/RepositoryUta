from fastapi import Request
from slowapi import Limiter

# Constante en codigo, no en Settings: el .NET la tiene hardcodeada en
# Program.cs (FixedWindowLimiter), no en appsettings.json — misma decision
# aca (regla de Fase 1 sobre constantes vs. tablas de parametrizacion).
LOGIN_RATE_LIMIT = "6/minute"


def get_client_ip(request: Request) -> str:
    """Espejo de AuthController.GetClientIp: X-Forwarded-For > X-Real-IP > IP
    de conexion directa, normalizando loopback IPv6 a 127.0.0.1.

    Usada como key_func del limiter: detras de un reverse proxy,
    slowapi.util.get_remote_address ve siempre la IP del proxy para TODO el
    trafico, asi que el cupo de LOGIN_RATE_LIMIT terminaba compartido por
    todos los clientes reales en vez de aplicarse por cliente (2026-09-21)."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    ip = request.client.host if request.client else None
    return "127.0.0.1" if ip == "::1" else (ip or "unknown")


limiter = Limiter(key_func=get_client_ip)
