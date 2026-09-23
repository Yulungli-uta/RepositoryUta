import base64
import logging
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import jwt as pyjwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.core.security.password import verify_password
from repositoryuta.models.rbac import Permission, Role, RolePermission
from repositoryuta.repositories.access_profile_repository import AccessProfileRepository
from repositoryuta.repositories.application_repository import ApplicationRepository
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.session_repository import SessionRepository
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.schemas.audit import LoginHistoryCreate
from repositoryuta.schemas.auth import MeResponse, TokenPair, ValidateTokenResponse
from repositoryuta.services import local_ad_service, token_service

logger = logging.getLogger(__name__)

REFRESH_TOKEN_TTL_DAYS = 7
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 30
REFRESH_REUSE_GRACE_SECONDS = 60


def get_ad_groups(email: str) -> list[str]:
    """Espejo de AuthService.GetAdGroupsAsync / AzureAuthService.GetAdGroupsAsync:
    busca el usuario en el AD local por email y lee sus grupos. Cualquier
    fallo (AD no configurado, no encontrado, error de red/bind) se trata como
    no bloqueante y retorna lista vacia — el login nunca debe fallar por un
    problema de AD, igual que el .NET real.
    """
    try:
        ad_user = local_ad_service.find_user_by_email(email)
        if ad_user is None:
            logger.info("[AD-GROUPS] Usuario %s no encontrado en AD local, se omiten grupos", email)
            return []
        groups = local_ad_service.get_user_groups(ad_user.id)
        names = [g.name for g in groups]
        logger.info("[AD-GROUPS] %s grupos obtenidos del AD para %s: %s", len(names), email, names)
        return names
    except Exception:
        logger.exception("[AD-GROUPS] Error al consultar AD para %s, se continua sin grupos", email)
        return []


def _generate_refresh_token() -> str:
    """Espejo de Convert.ToBase64String(RandomNumberGenerator.GetBytes(48))."""
    return base64.b64encode(secrets.token_bytes(48)).decode("ascii")


def login_local(
    session: Session,
    email: str,
    password: str,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
    device_info: str | None = None,
    browser_id: str | None = None,
) -> TokenPair | None:
    """Espejo de AuthService.LoginLocalAsync — mismo orden de validaciones,
    mismos umbrales (5 intentos, bloqueo 30 min, sesion 7 dias).
    """
    now = datetime.now()
    users = UserRepository(session)
    sessions = SessionRepository(session)

    def _log_failed(user_id: UUID | None, status: str, reason: str) -> None:
        AuditRepository(session).insert_login(
            LoginHistoryCreate(
                user_id=user_id,
                login_type="Local",
                login_status=status,
                failure_reason=reason,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
            )
        )

    user = users.find_by_email(email)
    if user is None or not user.is_active or (user.user_type or "").lower() != "local":
        sessions.record_failed_attempt(email, None, None, "User not found/inactive")
        _log_failed(None, "Failed", "User not found/inactive")
        return None

    cred = users.get_local_credential(user.id)
    if cred is None:
        sessions.record_failed_attempt(email, None, None, "No credentials")
        _log_failed(user.id, "Failed", "No credentials")
        return None

    if cred.is_locked or (cred.locked_until is not None and cred.locked_until > now):
        _log_failed(user.id, "Blocked", "Locked account")
        return None

    if cred.password_expires_at is not None and cred.password_expires_at <= now:
        _log_failed(user.id, "Failed", "Password expired")
        return None

    if not verify_password(password, cred.password_hash):
        cred.failed_attempts += 1
        cred.last_failed_attempt = now
        if cred.failed_attempts >= MAX_FAILED_ATTEMPTS:
            cred.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            cred.is_locked = True
        sessions.record_failed_attempt(email, None, None, "Invalid password")
        _log_failed(user.id, "Blocked" if cred.is_locked else "Failed", "Invalid password")
        return None

    cred.failed_attempts = 0
    cred.is_locked = False
    cred.locked_until = None

    roles = users.get_roles(user.id)
    ad_groups = get_ad_groups(user.email)
    hr_employee_id = users.get_hr_employee_id(user.id)

    new_session_id = uuid4()
    access_token = jwt_core.create_user_token(
        str(user.id),
        user.email,
        roles,
        ad_groups=ad_groups,
        employee_id=hr_employee_id,
        session_id=str(new_session_id),
    )
    refresh_token = _generate_refresh_token()
    refresh_hash = token_service.hash_token(refresh_token)

    session_row = sessions.create_session(
        user_id=user.id,
        access_token=access_token,
        refresh_token_hash=refresh_hash,
        expires_at=now + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
        device=device_info,
        ip_address=ip_address,
        user_agent=user_agent,
        browser_id=browser_id,
        session_id=new_session_id,
    )
    users.set_last_login(user.id, now)

    AuditRepository(session).insert_login(
        LoginHistoryCreate(
            user_id=user.id,
            login_type="Local",
            login_status="Success",
            session_id=session_row.session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )
    )
    logger.info("Login exitoso para %s, SessionId: %s", email, session_row.session_id)
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


def refresh(session: Session, refresh_token: str) -> TokenPair | None:
    """Espejo de AuthService.RefreshAsync: rota el refresh token heredando
    device/ip/user_agent/browser_id de la sesion anterior (a diferencia del
    login, aqui SI se heredan)."""
    sessions = SessionRepository(session)
    users = UserRepository(session)
    refresh_hash = token_service.hash_token(refresh_token)

    found = sessions.get_active_session_by_refresh_hash(refresh_hash)
    if found is None:
        _detect_refresh_token_reuse(session, refresh_hash)
        return None

    old_session, user = found
    roles = users.get_roles(user.id)
    ad_groups = get_ad_groups(user.email)
    hr_employee_id = users.get_hr_employee_id(user.id)

    new_session_id = uuid4()
    new_access = jwt_core.create_user_token(
        str(user.id),
        user.email,
        roles,
        ad_groups=ad_groups,
        employee_id=hr_employee_id,
        session_id=str(new_session_id),
    )
    new_refresh_token = _generate_refresh_token()
    new_hash = token_service.hash_token(new_refresh_token)
    new_expiry = datetime.now() + timedelta(days=REFRESH_TOKEN_TTL_DAYS)

    sessions.revoke_session(old_session.session_id, "Rotated")
    sessions.create_session(
        user_id=user.id,
        access_token=new_access,
        refresh_token_hash=new_hash,
        expires_at=new_expiry,
        device=old_session.device_info,
        ip_address=old_session.ip_address,
        user_agent=old_session.user_agent,
        browser_id=old_session.browser_id,
        session_id=new_session_id,
    )
    return TokenPair(access_token=new_access, refresh_token=new_refresh_token)


def _detect_refresh_token_reuse(session: Session, refresh_hash: str) -> None:
    """Deteccion de reuso de refresh tokens rotados (OAuth 2.0 Security BCP).

    Best-effort: un fallo aqui nunca debe alterar la respuesta del refresh —
    mismo try/except-todo que DetectRefreshTokenReuseAsync en .NET.
    """
    try:
        sessions = SessionRepository(session)
        rotated = sessions.get_rotated_session_by_refresh_hash(refresh_hash)
        if rotated is None:
            return  # hash desconocido: token invalido normal, sin accion

        # Sesiones rotadas antes de este cambio no tienen revoked_at: sin dato
        # fiable de cuando se roto, no se castiga (evita falsos positivos).
        if rotated.revoked_at is None:
            return

        if datetime.now() - rotated.revoked_at <= timedelta(seconds=REFRESH_REUSE_GRACE_SECONDS):
            return  # ventana de gracia para refresh concurrentes legitimos

        revoked_count = sessions.revoke_all_active_sessions_for_user(
            rotated.user_id, "RefreshReuse"
        )

        AuditRepository(session).insert_login(
            LoginHistoryCreate(
                user_id=rotated.user_id,
                login_type="Refresh",
                login_status="TokenReuse",
                failure_reason=f"Reuso de refresh token rotado; {revoked_count} sesiones revocadas",
                session_id=rotated.session_id,
                ip_address=rotated.ip_address,
                user_agent=rotated.user_agent,
                device_info=rotated.device_info,
            )
        )
        logger.warning(
            "Reuso de refresh token detectado. UserId: %s, sesion origen: %s, "
            "sesiones revocadas: %s",
            rotated.user_id,
            rotated.session_id,
            revoked_count,
        )
    except Exception:
        logger.exception("Error en la deteccion de reuso de refresh token")


def logout(session: Session, refresh_token: str) -> bool:
    """Espejo de AuthService.LogoutAsync — idempotente: si no encuentra la
    sesion, igual retorna exito."""
    sessions = SessionRepository(session)
    refresh_hash = token_service.hash_token(refresh_token)
    found = sessions.get_active_session_by_refresh_hash(refresh_hash)
    if found is None:
        return True
    session_row, _ = found
    sessions.revoke_session(session_row.session_id, "Logout")
    return True


def _looks_like_jwt(token: str) -> bool:
    """Aproximacion de JwtSecurityTokenHandler.CanReadToken: 3 segmentos no
    vacios separados por punto."""
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def validate_token(session: Session, token: str) -> ValidateTokenResponse:
    """Espejo de AuthService.ValidateTokenAsync.

    Nota: el .NET acepta un parametro `clientId` en la firma que NUNCA se usa
    dentro del metodo — se omite aqui, no es una omision.

    Importante: la rama de "token opaco" (GUID de sesion) solo se intenta
    cuando el string NO tiene forma de JWT. Un JWT bien formado pero invalido
    (firma/issuer/expiracion) NUNCA cae a esa rama en el .NET real — aqui se
    replica esa misma separacion, no se combinan ambas rutas.
    """
    try:
        if _looks_like_jwt(token):
            try:
                payload = jwt_core.decode_token(token)
            except pyjwt.ExpiredSignatureError:
                return ValidateTokenResponse(
                    is_valid=False, token_type="Unknown", message="Token expired", email=""
                )
            except Exception:
                return ValidateTokenResponse(
                    is_valid=False,
                    token_type="Unknown",
                    message="Token validation failed",
                    email="",
                )

            expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)

            # Tokens emitidos antes de este chequeo no traen "sid" — se validan igual
            # que siempre (sin esto, cualquier sesion activa quedaria deslogueada al
            # desplegar este cambio).
            sid_raw = payload.get("sid")
            sid: UUID | None = None
            if sid_raw is not None:
                try:
                    sid = UUID(str(sid_raw))
                except (ValueError, TypeError):
                    sid = None
                if sid is not None:
                    session_active = SessionRepository(session).is_session_active(sid)
                    if session_active is False:
                        return ValidateTokenResponse(
                            is_valid=False,
                            token_type="JWT",
                            session_id=sid,
                            message="Sesión revocada",
                            email="",
                        )

            user_id_raw = payload.get(jwt_core.CLAIM_NAME_IDENTIFIER) or payload.get("sub")
            try:
                user_id = UUID(str(user_id_raw))
            except (ValueError, TypeError):
                user_id = None

            if user_id is not None:
                user = UserRepository(session).find_by_id(user_id)
                if user is not None and user.is_active:
                    return ValidateTokenResponse(
                        is_valid=True,
                        token_type="JWT",
                        expires_at=expires_at,
                        user_id=user_id,
                        session_id=sid,
                        message="Token is valid",
                        email=user.email,
                    )

            client_id = payload.get("client_id")
            if client_id and ApplicationRepository(session).exists_active_client(client_id):
                return ValidateTokenResponse(
                    is_valid=True,
                    token_type="AppToken",
                    expires_at=expires_at,
                    message="Token is valid",
                    email=client_id,
                )

            return ValidateTokenResponse(
                is_valid=False,
                token_type="Unknown",
                message="User not found or inactive",
                email="",
            )

        try:
            session_id = UUID(token)
        except ValueError:
            return ValidateTokenResponse(
                is_valid=False,
                token_type="Unknown",
                message="Token is invalid or expired",
                email="",
            )

        session_row = SessionRepository(session).find_active_by_session_id(session_id)
        if session_row is not None:
            return ValidateTokenResponse(
                is_valid=True,
                token_type="User token",
                expires_at=session_row.expires_at,
                user_id=session_row.user_id,
                session_id=session_row.session_id,
                message="Token is valid",
                email="",
            )

        return ValidateTokenResponse(
            is_valid=False, token_type="Unknown", message="Token is invalid or expired", email=""
        )
    except Exception:
        logger.exception("Error al validar token")
        return ValidateTokenResponse(
            is_valid=False, token_type="Unknown", message="Error validating token", email=""
        )


def get_me(session: Session, user_id: UUID) -> MeResponse | None:
    """Espejo de AuthService.MeAsync: perfil + roles + permisos efectivos +
    nombres de AccessProfile (informativo, no participa en la autorizacion)."""
    users = UserRepository(session)
    user = users.find_by_id(user_id)
    if user is None:
        return None

    roles = users.get_roles(user_id)
    personnel_email = users.get_personnel_email(user_id)

    action_permissions_stmt = (
        select(Permission.module, Permission.action)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(Role, Role.id == RolePermission.role_id)
        .where(
            Role.name.in_(roles),
            Role.is_active,
            ~Role.is_deleted,
            ~Permission.is_deleted,
        )
    )
    action_permissions = sorted(
        {
            f"{module}.{action}".upper()
            for module, action in session.execute(action_permissions_stmt)
        }
    )

    profiles = [p.name for p in AccessProfileRepository(session).get_profiles_for_user(user_id)]

    return MeResponse(
        id=user.id,
        email=user.email,
        personnel_email=personnel_email,
        display_name=user.display_name,
        user_type=user.user_type,
        last_login=user.last_login,
        roles=roles,
        action_permissions=action_permissions,
        profiles=profiles,
    )
