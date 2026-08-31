from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from repositoryuta.core.rate_limit import LOGIN_RATE_LIMIT, limiter
from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.app_auth import AppAuthRequest, LegacyAuthRequest
from repositoryuta.schemas.auth import ValidateTokenRequest
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import app_auth_service

# Espejo de AppAuthController.cs: autenticacion app-a-app, sin [Authorize] a
# nivel de clase (cada accion decide su propio requisito).
router = APIRouter(prefix="/api/app-auth", tags=["app-auth"])


@router.post("/token")
@limiter.limit(LOGIN_RATE_LIMIT)
def get_application_token(
    request: Request,
    dto: AppAuthRequest,
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """[AllowAnonymous] + rate limit, igual que /api/auth/login."""
    result = app_auth_service.authenticate_application(
        session,
        dto.client_id,
        dto.client_secret,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    if not result.success:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=result.message)
    return ApiResponse.ok(dump(result), "Application authenticated successfully")


@router.post("/legacy-login")
@limiter.limit(LOGIN_RATE_LIMIT)
def legacy_login(
    request: Request,
    dto: LegacyAuthRequest,
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """[AllowAnonymous] + rate limit, igual que /api/auth/login."""
    result = app_auth_service.authenticate_user_legacy(
        session,
        dto.client_id,
        dto.client_secret,
        dto.user_email,
        dto.password,
        dto.include_permissions if dto.include_permissions is not None else True,
        request.client.host if request.client else None,
        request.headers.get("user-agent"),
    )
    if not result.success:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=result.message)
    return ApiResponse.ok(dump(result), "User authenticated successfully")


@router.post("/validate-token")
def validate_token(
    dto: ValidateTokenRequest,
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """[AllowAnonymous]: siempre 200, el resultado va en el payload
    (`IsValid`), igual que el .NET real."""
    result = app_auth_service.validate_token(session, dto.token, dto.client_id)
    message = "Token is valid" if result.is_valid else "Token validation result"
    return ApiResponse.ok(dump(result), message)


@router.get("/stats/{client_id}")
def get_application_stats(
    client_id: str,
    session: Session = Depends(get_db_session),
    _actor_id=Depends(get_current_user_id),
) -> ApiResponse:
    """[Authorize] simple, sin restriccion de rol."""
    stats = app_auth_service.get_application_stats(session, client_id)
    if stats is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Application not found")
    return ApiResponse.ok(dump(stats), "Application statistics retrieved")
