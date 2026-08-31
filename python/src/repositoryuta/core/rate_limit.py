from slowapi import Limiter
from slowapi.util import get_remote_address

# Constante en codigo, no en Settings: el .NET la tiene hardcodeada en
# Program.cs (FixedWindowLimiter), no en appsettings.json — misma decision
# aca (regla de Fase 1 sobre constantes vs. tablas de parametrizacion).
LOGIN_RATE_LIMIT = "6/minute"

limiter = Limiter(key_func=get_remote_address)
