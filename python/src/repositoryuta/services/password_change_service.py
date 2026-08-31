import secrets
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy.orm import Session

from repositoryuta.core.security.password import hash_password, verify_password
from repositoryuta.models.identity import LocalUserCredential, PasswordHistory
from repositoryuta.repositories.security_token_repository import SecurityTokenRepository
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.schemas.identity import (
    ChangePasswordResponse,
    RequestPasswordChange2FAResponse,
)
from repositoryuta.services import token_service

OTP_TOKEN_TYPE = "PasswordChange2FA"
OTP_TTL_MINUTES = 10
PASSWORD_EXPIRY_DAYS = 90

_COMPLEXITY_MESSAGE = (
    "La nueva contraseña no cumple los requisitos: "
    "mínimo 8 caracteres, una mayúscula y un número"
)


def _is_password_complex(password: str) -> bool:
    """Espejo de AuthService.IsPasswordComplex: min 8 caracteres, 1 mayuscula,
    1 digito. Es la validacion REAL que aplica el flujo vivo —
    fn_ValidatePasswordStrength (SQL, configurable via AppParams) esta
    muerta/sin usar (confirmado en Fase 0)."""
    return (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )


def _generate_otp() -> str:
    """Espejo de GenerateOtp: 6 digitos numericos. Se usa secrets.randbelow en
    vez del mod de un int32 aleatorio del .NET — mismo contrato (string de 6
    digitos), sin el sesgo minusculo de ese mod ni su bug teorico de overflow
    en Math.Abs(int.MinValue)."""
    return f"{secrets.randbelow(1_000_000):06d}"


def _apply_password_change(
    session: Session, user_id: UUID, cred: LocalUserCredential, new_password: str
) -> None:
    """Espejo de ApplyPasswordChangeAsync."""
    new_hash = hash_password(new_password)
    now = datetime.now()

    cred.password_hash = new_hash
    cred.password_created_at = now
    cred.must_change_password = False
    cred.password_expires_at = now + timedelta(days=PASSWORD_EXPIRY_DAYS)
    cred.failed_attempts = 0
    cred.is_locked = False

    session.add(PasswordHistory(user_id=user_id, password_hash=new_hash, created_at=now))
    session.flush()


def change_password(
    session: Session, user_id: UUID, current_password: str, new_password: str
) -> ChangePasswordResponse:
    """Espejo de AuthService.ChangePasswordAsync — orden de checks preservado
    tal cual: actual -> igual-a-la-actual -> complejidad."""
    users = UserRepository(session)
    user = users.find_by_id(user_id)
    if user is None or not user.is_active:
        return ChangePasswordResponse(success=False, message="Usuario no encontrado o inactivo")

    if (user.user_type or "").lower() != "local":
        return ChangePasswordResponse(
            success=False,
            message="Este usuario es de tipo AD/Azure y no puede cambiar su contraseña desde aquí",
        )

    cred = users.get_local_credential(user_id)
    if cred is None:
        return ChangePasswordResponse(
            success=False, message="El usuario no tiene credenciales locales"
        )

    if not verify_password(current_password, cred.password_hash):
        return ChangePasswordResponse(success=False, message="La contraseña actual es incorrecta")

    if verify_password(new_password, cred.password_hash):
        return ChangePasswordResponse(
            success=False, message="La nueva contraseña no puede ser igual a la actual"
        )

    if not _is_password_complex(new_password):
        return ChangePasswordResponse(success=False, message=_COMPLEXITY_MESSAGE)

    _apply_password_change(session, user_id, cred, new_password)
    return ChangePasswordResponse(success=True, message="Contraseña cambiada exitosamente")


def request_password_change_2fa(
    session: Session, user_id: UUID, *, is_development: bool = False
) -> RequestPasswordChange2FAResponse:
    """Espejo de AuthService.RequestPasswordChange2FAAsync."""
    users = UserRepository(session)
    user = users.find_by_id(user_id)
    if user is None or not user.is_active:
        return RequestPasswordChange2FAResponse(
            success=False, message="Usuario no encontrado o inactivo"
        )

    if (user.user_type or "").lower() == "local":
        cred = users.get_local_credential(user_id)
        if cred is None:
            return RequestPasswordChange2FAResponse(
                success=False, message="El usuario no tiene credenciales locales"
            )

    tokens = SecurityTokenRepository(session)
    tokens.invalidate_pending(user_id, OTP_TOKEN_TYPE)

    otp_code = _generate_otp()
    tokens.create(
        user_id=user_id,
        token_type=OTP_TOKEN_TYPE,
        token_hash=token_service.hash_token(otp_code),
        expires_at=datetime.now() + timedelta(minutes=OTP_TTL_MINUTES),
        additional_data=str(user_id),
    )

    return RequestPasswordChange2FAResponse(
        success=True,
        message="Código OTP generado. Válido por 10 minutos.",
        otp_code_dev=otp_code if is_development else None,
    )


def change_password_with_2fa(
    session: Session,
    user_id: UUID,
    current_password: str,
    new_password: str,
    otp_code: str,
) -> ChangePasswordResponse:
    """Espejo de AuthService.ChangePasswordWith2FAAsync — OJO: orden de checks
    distinto al de change_password() (aqui complejidad va ANTES que
    igual-a-la-actual). Es una inconsistencia real del .NET; se preserva."""
    users = UserRepository(session)
    user = users.find_by_id(user_id)
    if user is None or not user.is_active or (user.user_type or "").lower() != "local":
        return ChangePasswordResponse(
            success=False, message="Usuario no válido para esta operación"
        )

    cred = users.get_local_credential(user_id)
    if cred is None:
        return ChangePasswordResponse(
            success=False, message="El usuario no tiene credenciales locales"
        )

    if not verify_password(current_password, cred.password_hash):
        return ChangePasswordResponse(success=False, message="La contraseña actual es incorrecta")

    if not _is_password_complex(new_password):
        return ChangePasswordResponse(success=False, message=_COMPLEXITY_MESSAGE)

    if verify_password(new_password, cred.password_hash):
        return ChangePasswordResponse(
            success=False, message="La nueva contraseña no puede ser igual a la actual"
        )

    tokens = SecurityTokenRepository(session)
    token = tokens.find_valid(user_id, OTP_TOKEN_TYPE, token_service.hash_token(otp_code))
    if token is None:
        return ChangePasswordResponse(
            success=False, message="El código OTP es inválido o ha expirado"
        )

    tokens.consume(token)
    _apply_password_change(session, user_id, cred, new_password)
    return ChangePasswordResponse(success=True, message="Contraseña cambiada exitosamente")


def verify_and_consume_password_otp(
    session: Session, user_id: UUID, otp_code: str
) -> ChangePasswordResponse:
    """Espejo de AuthService.VerifyAndConsumePasswordOtpAsync."""
    tokens = SecurityTokenRepository(session)
    token = tokens.find_valid(user_id, OTP_TOKEN_TYPE, token_service.hash_token(otp_code))
    if token is None:
        return ChangePasswordResponse(
            success=False, message="El código OTP es inválido o ha expirado"
        )

    tokens.consume(token)
    return ChangePasswordResponse(success=True, message="OTP verificado")
