import base64
import logging
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from repositoryuta.config import get_settings

logger = logging.getLogger(__name__)

# Mismos Claim.Type largos que emite JwtTokenService.cs (ClaimTypes.* de .NET).
# Se preservan literales para que un token emitido por Python sea indistinguible,
# a nivel de wire format, de uno emitido por el .NET actual.
CLAIM_NAME_IDENTIFIER = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
CLAIM_NAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
CLAIM_ROLE = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"


class RsaKeyProvider:
    def __init__(self, private_key: RSAPrivateKey, key_id: str) -> None:
        self.private_key = private_key
        self.public_key: RSAPublicKey = private_key.public_key()
        self.key_id = key_id


def _load_configured_private_key() -> RSAPrivateKey | None:
    settings = get_settings()
    pem_bytes: bytes | None = None

    if settings.jwt.private_key_pem:
        pem_bytes = settings.jwt.private_key_pem.encode("utf-8")
    elif settings.jwt.private_key_path and settings.jwt.private_key_path.exists():
        pem_bytes = settings.jwt.private_key_path.read_bytes()

    if pem_bytes is None:
        return None
    return serialization.load_pem_private_key(pem_bytes, password=None)


@lru_cache(maxsize=1)
def get_rsa_key_provider() -> RsaKeyProvider:
    """Espejo de RsaKeyProvider.cs: PEM inline o archivo; en development sin
    ninguno de los dos, genera una clave efimera con warning; en cualquier
    otro ambiente, falla explicito (no bloquear el arranque en silencio).
    """
    settings = get_settings()
    private_key = _load_configured_private_key()

    if private_key is None:
        # "test" tambien genera clave efimera (ademas de "development"): las pruebas
        # automatizadas no deben requerir una clave RSA real para correr. "validation"
        # queda fuera a proposito porque simula un ambiente pre-productivo real.
        if settings.app_env in {"development", "test"}:
            logger.warning(
                "jwt.private_key_pem/private_key_path no configurados. Generando clave RSA "
                "efimera SOLO para development/test. Los tokens no seran validos tras "
                "reiniciar el proceso."
            )
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        else:
            raise RuntimeError(
                "jwt.private_key_pem o jwt.private_key_path deben estar configurados "
                "fuera de development/test."
            )

    return RsaKeyProvider(private_key, settings.jwt.key_id)


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8 or 1
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode("ascii")


def get_jwks() -> dict[str, Any]:
    provider = get_rsa_key_provider()
    numbers = provider.public_key.public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": provider.key_id,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


def create_user_token(
    user_id: str,
    email: str,
    roles: list[str],
    *,
    ad_groups: list[str] | None = None,
    employee_id: int | None = None,
    lifetime_minutes: int | None = None,
    session_id: str | None = None,
) -> str:
    """Espejo de JwtTokenService.CreateAsync (token de usuario)."""
    settings = get_settings()
    provider = get_rsa_key_provider()
    lifetime = timedelta(minutes=lifetime_minutes or settings.jwt.access_token_lifetime_minutes)
    now = datetime.now(UTC)

    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "jti": str(uuid.uuid4()),
        CLAIM_NAME_IDENTIFIER: user_id,
        CLAIM_NAME: email,
        CLAIM_ROLE: list(roles),
        "iss": settings.jwt.issuer,
        "aud": settings.jwt.audience,
        "iat": now,
        "exp": now + lifetime,
    }
    if ad_groups:
        payload["ad_group"] = list(ad_groups)
    if employee_id is not None:
        payload["employeeId"] = employee_id
    # Vincula el token a una fila concreta de auth.tbl_UserSessions: sin este claim,
    # revocar una sesion en BD no tenia ningun efecto sobre un access token ya emitido
    # (solo bloqueaba el refresh) — validate_token lo usa para chequear revocacion.
    if session_id is not None:
        payload["sid"] = session_id

    return pyjwt.encode(
        payload, provider.private_key, algorithm="RS256", headers={"kid": provider.key_id}
    )


def create_app_token(
    token_id: str,
    client_id: str,
    roles: list[str],
    lifetime_minutes: int,
) -> str:
    """Espejo de JwtTokenService.CreateAppTokenAsync (token de aplicacion, client_credentials).

    Sin claims de usuario (email/nameidentifier): lleva client_id + token_use="app"
    para que el validador lo resuelva contra auth.tbl_Applications, no auth.tbl_Users.
    """
    settings = get_settings()
    provider = get_rsa_key_provider()
    now = datetime.now(UTC)

    payload: dict[str, Any] = {
        "sub": token_id,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
        "token_use": "app",
        CLAIM_ROLE: list(roles),
        "iss": settings.jwt.issuer,
        "aud": settings.jwt.audience,
        "iat": now,
        "exp": now + timedelta(minutes=lifetime_minutes),
    }

    return pyjwt.encode(
        payload, provider.private_key, algorithm="RS256", headers={"kid": provider.key_id}
    )


def decode_token(token: str) -> dict[str, Any]:
    """Valida firma/issuer/audience/expiracion unicamente.

    La revocacion contra sesiones/lista negra en BD es responsabilidad del
    servicio/repositorio que llame a esto (Fase 4), no de esta utilidad.
    Propaga las excepciones de PyJWT (ExpiredSignatureError, InvalidTokenError...);
    el router es quien decide el mensaje seguro que ve el cliente (Fase 5).
    """
    settings = get_settings()
    provider = get_rsa_key_provider()
    return pyjwt.decode(
        token,
        provider.public_key,
        algorithms=["RS256"],
        issuer=settings.jwt.issuer,
        audience=settings.jwt.audience,
    )


def roles_from_payload(payload: dict[str, Any]) -> list[str]:
    """PyJWT no colapsa un unico rol a string, pero el token puede venir de
    otra fuente (o de un test) con esa forma; normaliza ambos casos.
    """
    roles = payload.get(CLAIM_ROLE, [])
    if isinstance(roles, str):
        return [roles]
    return list(roles)
