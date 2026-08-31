import hmac
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.core.security.password import verify_password
from repositoryuta.models.rbac import Permission, Role, RolePermission, UserRole
from repositoryuta.repositories.application_repository import ApplicationRepository
from repositoryuta.repositories.session_repository import SessionRepository
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.schemas.app_auth import (
    AppAuthResponse,
    ApplicationStatsRead,
    LegacyAuthResponse,
    LegacyPermissionInfo,
    LegacyRoleInfo,
)
from repositoryuta.schemas.application import LegacyAuthLogCreate
from repositoryuta.schemas.auth import ValidateTokenResponse
from repositoryuta.services import token_service
from repositoryuta.services.auth_service import MAX_FAILED_ATTEMPTS

# Espejo de AppAuthService.cs: autenticacion app-a-app (client credentials) y
# login legacy de un usuario final via una app cliente. Sin dependencia de
# Azure/LocalAd — DB local + hashing puro, por eso no estaba bloqueado por la
# regla de Fase 0 #13, solo nunca se habia mapeado (Grupo C, 2026-08-27).

_APP_TOKEN_LIFETIME_MINUTES = 60


def _secret_matches(expected_hash: str, actual_hash: str) -> bool:
    """Espejo de AppAuthService.SecretMatches: comparacion en tiempo constante."""
    return hmac.compare_digest(expected_hash.encode("utf-8"), actual_hash.encode("utf-8"))


def authenticate_application(
    session: Session,
    client_id: str,
    client_secret: str,
    ip_address: str | None,
    user_agent: str | None,
) -> AppAuthResponse:
    apps = ApplicationRepository(session)
    app = apps.find_active_by_client_id(client_id)
    if app is None or not _secret_matches(
        app.client_secret_hash, token_service.hash_token(client_secret)
    ):
        return AppAuthResponse(success=False, message="Invalid client credentials")

    token_id = uuid4()
    settings = get_settings()
    configured_roles = settings.app_auth.client_roles.get(app.client_id)
    token_roles = configured_roles if configured_roles else ["Application"]
    token = jwt_core.create_app_token(
        str(token_id), app.client_id, token_roles, _APP_TOKEN_LIFETIME_MINUTES
    )

    now = datetime.now()
    app.last_used_at = now
    apps.log_legacy_auth(
        LegacyAuthLogCreate(
            application_id=app.id,
            user_email=app.client_id,
            auth_result="Success",
            ip_address=ip_address or "",
            user_agent=user_agent or "",
        )
    )

    return AppAuthResponse(
        success=True,
        message="Authentication successful",
        access_token=token,
        token_id=token_id,
        expires_at=now + timedelta(minutes=_APP_TOKEN_LIFETIME_MINUTES),
        application_id=app.id,
    )


def _log_legacy_attempt(
    session: Session,
    application_id: UUID,
    user_id: UUID | None,
    user_email: str,
    auth_result: str,
    failure_reason: str | None,
    ip_address: str | None,
    user_agent: str | None,
    start_time: datetime,
) -> None:
    response_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
    ApplicationRepository(session).log_legacy_auth(
        LegacyAuthLogCreate(
            application_id=application_id,
            user_id=user_id,
            user_email=user_email,
            auth_result=auth_result,
            failure_reason=failure_reason,
            ip_address=ip_address,
            user_agent=user_agent,
            response_time=response_time_ms,
        )
    )


def _active_roles_and_permissions(
    session: Session, user_id: UUID
) -> tuple[list[LegacyRoleInfo], list[LegacyPermissionInfo]]:
    now = datetime.now()
    active_user_roles = select(UserRole.role_id).where(
        UserRole.user_id == user_id,
        ~UserRole.is_deleted,
        (UserRole.expires_at.is_(None)) | (UserRole.expires_at > now),
    )

    roles_stmt = select(Role.id, Role.name, Role.description).where(
        Role.id.in_(active_user_roles)
    )
    roles = [
        LegacyRoleInfo(id=row.id, name=row.name, description=row.description)
        for row in session.execute(roles_stmt)
    ]

    permissions_stmt = (
        select(
            Permission.id,
            Permission.name,
            Permission.module,
            Permission.action,
            Permission.description,
        )
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .where(RolePermission.role_id.in_(active_user_roles), ~Permission.is_deleted)
        .distinct()
    )
    permissions = [
        LegacyPermissionInfo(
            id=row.id,
            name=row.name,
            module=row.module,
            action=row.action,
            description=row.description,
        )
        for row in session.execute(permissions_stmt)
    ]
    return roles, permissions


def authenticate_user_legacy(
    session: Session,
    client_id: str,
    client_secret: str,
    user_email: str,
    password: str,
    include_permissions: bool,
    ip_address: str | None,
    user_agent: str | None,
) -> LegacyAuthResponse:
    """Espejo de AppAuthService.AuthenticateUserLegacyAsync."""
    start_time = datetime.now()
    apps = ApplicationRepository(session)
    app = apps.find_active_by_client_id(client_id)
    if app is None:
        return LegacyAuthResponse(success=False, message="Invalid application")

    if not _secret_matches(app.client_secret_hash, token_service.hash_token(client_secret)):
        _log_legacy_attempt(
            session,
            app.id,
            None,
            user_email,
            "Failed",
            "Invalid application credentials",
            ip_address,
            user_agent,
            start_time,
        )
        return LegacyAuthResponse(success=False, message="Invalid application credentials")

    users = UserRepository(session)
    user = users.find_by_email(user_email)
    if user is None:
        _log_legacy_attempt(
            session, app.id, None, user_email, "Failed", "User not found",
            ip_address, user_agent, start_time,
        )
        return LegacyAuthResponse(success=False, message="User not found")

    if not user.is_active:
        _log_legacy_attempt(
            session, app.id, user.id, user_email, "Failed", "User is inactive",
            ip_address, user_agent, start_time,
        )
        return LegacyAuthResponse(success=False, message="User is inactive")

    if user.user_type == "AzureAD":
        reason = "Azure AD users must authenticate through Azure"
        _log_legacy_attempt(
            session, app.id, user.id, user_email, "Failed", reason,
            ip_address, user_agent, start_time,
        )
        return LegacyAuthResponse(success=False, message=reason)

    if user.user_type == "Local":
        credentials = users.get_local_credential(user.id)
        if credentials is None:
            _log_legacy_attempt(
                session, app.id, user.id, user_email, "Failed", "No local credentials found",
                ip_address, user_agent, start_time,
            )
            return LegacyAuthResponse(success=False, message="No local credentials found")

        if credentials.is_locked:
            _log_legacy_attempt(
                session, app.id, user.id, user_email, "Failed", "Account is locked",
                ip_address, user_agent, start_time,
            )
            return LegacyAuthResponse(success=False, message="Account is locked")

        if not verify_password(password, credentials.password_hash):
            credentials.failed_attempts += 1
            credentials.last_failed_attempt = datetime.now()
            if credentials.failed_attempts >= MAX_FAILED_ATTEMPTS:
                credentials.is_locked = True
            session.flush()
            _log_legacy_attempt(
                session, app.id, user.id, user_email, "Failed", "Invalid password",
                ip_address, user_agent, start_time,
            )
            return LegacyAuthResponse(success=False, message="Invalid password")

        credentials.failed_attempts = 0
        credentials.last_failed_attempt = None
        session.flush()

    user.last_login = datetime.now()
    session.flush()

    response = LegacyAuthResponse(
        success=True,
        message="Authentication successful",
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        user_type=user.user_type,
    )

    if include_permissions:
        response.roles, response.permissions = _active_roles_and_permissions(session, user.id)

    _log_legacy_attempt(
        session, app.id, user.id, user_email, "Success", None, ip_address, user_agent, start_time
    )
    return response


def validate_token(session: Session, token: str, client_id: str | None) -> ValidateTokenResponse:
    """Espejo de AppAuthService.ValidateTokenAsync: DISTINTO de
    auth_service.validate_token (que valida JWT). Este solo revisa si `token`
    es el GUID de una UserSession activa — no decodifica JWT en absoluto,
    igual que el .NET real."""
    try:
        token_guid = UUID(token)
    except ValueError:
        return ValidateTokenResponse(
            is_valid=False, token_type="Unknown", message="Token is invalid or expired", email=""
        )

    session_row = SessionRepository(session).find_active_by_session_id(token_guid)
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


def get_application_stats(session: Session, client_id: str) -> ApplicationStatsRead | None:
    apps = ApplicationRepository(session)
    app = apps.find_by_client_id(client_id)
    if app is None:
        return None

    total, successful, last_7_days = apps.get_legacy_auth_log_stats(app.id)
    return ApplicationStatsRead(
        application_id=app.id,
        name=app.name,
        client_id=app.client_id,
        is_active=app.is_active,
        created_at=app.created_at,
        total_auth_attempts=total,
        successful_auths=successful,
        auths_last_7_days=last_7_days,
        active_tokens=0,
    )
