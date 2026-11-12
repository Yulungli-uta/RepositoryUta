import hashlib
import re

import bcrypt

_SHA256_HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Espejo exacto de Utilities/PasswordHasher.cs.

    Acepta BCrypt (prefijo "$2") y, como fallback legacy, un hash SHA-256 hex
    de 64 caracteres sin sal. El fallback sigue pendiente de retiro hasta
    confirmar (regla de Fase 0 #5) que auth.tbl_LocalUserCredentials no tiene
    filas con ese formato.
    """
    if hashed.startswith("$2"):
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

    if len(hashed) == 64 and _SHA256_HEX_RE.match(hashed):
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return digest.lower() == hashed.lower()

    return False
