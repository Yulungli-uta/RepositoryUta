import json
import logging
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.core.rate_limit import LOGIN_RATE_LIMIT, limiter
from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.auth import (
    AzureAuthUrlRequest,
    AzureExchangeRequest,
    LoginRequest,
    RefreshRequest,
    ValidateTokenRequest,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import ChangePasswordRequest, ChangePasswordWith2FARequest
from repositoryuta.services import auth_service, azure_auth_service, password_change_service

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> str | None:
    """Espejo de AuthController.GetClientIp: X-Forwarded-For > X-Real-IP > IP
    de conexion directa, normalizando loopback IPv6 a 127.0.0.1."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    ip = request.client.host if request.client else None
    return "127.0.0.1" if ip == "::1" else ip


def _device_info(request: Request) -> str | None:
    return request.headers.get("X-Device-Info") or None


@router.post("/login")
@limiter.limit(LOGIN_RATE_LIMIT)
def login(
    request: Request, body: LoginRequest, session: Session = Depends(get_db_session)
) -> ApiResponse:
    pair = auth_service.login_local(
        session,
        body.email,
        body.password,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        device_info=_device_info(request),
    )
    if pair is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    return ApiResponse.ok(dump(pair), "Login exitoso")


@router.post("/refresh")
def refresh(body: RefreshRequest, session: Session = Depends(get_db_session)) -> ApiResponse:
    pair = auth_service.refresh(session, body.refresh_token)
    if pair is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")
    return ApiResponse.ok(dump(pair))


@router.post("/logout")
def logout(body: RefreshRequest, session: Session = Depends(get_db_session)) -> ApiResponse:
    """Idempotente y sin revelar si el token era valido — igual que en .NET,
    LogoutAsync ya se comporta asi (siempre exito salvo body vacio)."""
    if not body.refresh_token or not body.refresh_token.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Refresh token requerido")

    auth_service.logout(session, body.refresh_token)
    return ApiResponse.ok(True, "Sesión cerrada")


@router.get("/me")
def me(
    user_id: UUID = Depends(get_current_user_id),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    result = auth_service.get_me(session, user_id)
    if result is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return ApiResponse.ok(dump(result))


@router.post("/validate-token")
def validate_token(
    body: ValidateTokenRequest, session: Session = Depends(get_db_session)
) -> ApiResponse:
    if not body.token:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Token is required")

    result = auth_service.validate_token(session, body.token)
    message = "Token válido" if result.is_valid else "Token inválido"
    return ApiResponse.ok(dump(result), message)


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    user_id: UUID = Depends(get_current_user_id),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """Espejo de AuthController.ChangePassword, acotado a usuarios Local.

    No se pre-consulta el usuario en el router para decidir Local/AzureAD
    (a diferencia del .NET, que sí lo hace para poder desviar a AD Local/Azure
    Graph — no portado): password_change_service.change_password() ya hace
    esa misma validacion y devuelve el mismo mensaje para AzureAD, sin gastar
    una segunda consulta a Users en este endpoint.
    """
    if not body.new_password or not body.new_password.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La nueva contraseña es requerida")
    if not body.current_password or not body.current_password.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="La contraseña actual es requerida para usuarios locales",
        )

    result = password_change_service.change_password(
        session, user_id, body.current_password, body.new_password
    )
    if not result.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=result.message)
    return ApiResponse.ok(dump(result))


@router.post("/request-password-change-2fa")
def request_password_change_2fa(
    user_id: UUID = Depends(get_current_user_id),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    settings = get_settings()
    result = password_change_service.request_password_change_2fa(
        session, user_id, is_development=(settings.app_env == "development")
    )
    if not result.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=result.message)
    return ApiResponse.ok(dump(result), result.message)


@router.post("/change-password-2fa")
def change_password_with_2fa(
    body: ChangePasswordWith2FARequest,
    user_id: UUID = Depends(get_current_user_id),
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    """Espejo de AuthController.ChangePasswordWith2FA, acotado a usuarios Local
    (mismo criterio que change_password: el servicio ya valida el tipo)."""
    if not body.new_password.strip() or not body.otp_code.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="La nueva contraseña y el código OTP son requeridos",
        )
    if not body.current_password or not body.current_password.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="La contraseña actual es requerida para usuarios locales",
        )

    result = password_change_service.change_password_with_2fa(
        session, user_id, body.current_password, body.new_password, body.otp_code
    )
    if not result.success:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=result.message)
    return ApiResponse.ok(dump(result), result.message)


@router.get("/password-change-method")
def get_password_change_method() -> ApiResponse:
    settings = get_settings()
    return ApiResponse.ok({"method": settings.password_change.method})


# ── Azure AD (OAuth2/PKCE) ────────────────────────────────────────────────────
#
# Espejo de las acciones azure/* de AuthController.cs. El relay del
# deliveryCode hacia la pestaña que abrió el popup (hoy solo por SignalR en el
# .NET) se agrega aquí vía window.opener.postMessage en el HTML de respuesta
# del callback — ADITIVO, no reemplaza nada: mientras el .NET siga sirviendo
# tráfico real, su broadcast por WebSocket sigue intacto. El lado HrFrontend
# necesita su propio cambio aditivo (escuchar postMessage además de SignalR)
# antes de que esto funcione end-to-end — pendiente de proponer y aprobar por
# separado, no se toca ese repo desde aquí.


@router.get("/azure/url")
@limiter.limit(LOGIN_RATE_LIMIT)
def azure_url_get(
    request: Request,
    clientId: str | None = None,
    browserId: str | None = None,
    codeChallenge: str | None = None,
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    try:
        url, state = azure_auth_service.build_auth_url(session, clientId, browserId, codeChallenge)
    except PermissionError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return ApiResponse.ok(
        {
            "url": url,
            "state": state,
            "clientId": clientId,
            "browserId": browserId,
            "message": f"Login habilitado para la aplicación {clientId}",
        }
    )


@router.post("/azure/url")
@limiter.limit(LOGIN_RATE_LIMIT)
def azure_url_post(
    request: Request, body: AzureAuthUrlRequest, session: Session = Depends(get_db_session)
) -> ApiResponse:
    try:
        url, state = azure_auth_service.build_auth_url(
            session, body.client_id, body.browser_id, body.code_challenge
        )
    except PermissionError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return ApiResponse.ok(
        {
            "url": url,
            "state": state,
            "clientId": body.client_id,
            "browserId": body.browser_id,
            "message": f"Login habilitado para la aplicación {body.client_id}",
        }
    )


@router.post("/azure/exchange")
@limiter.limit(LOGIN_RATE_LIMIT)
def azure_exchange(
    request: Request, body: AzureExchangeRequest, session: Session = Depends(get_db_session)
) -> ApiResponse:
    missing_fields = not body.delivery_code or not body.delivery_code.strip()
    missing_fields = missing_fields or not body.code_verifier or not body.code_verifier.strip()
    if missing_fields:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="deliveryCode y codeVerifier son requeridos"
        )

    pair = azure_auth_service.exchange_delivery_code(body.delivery_code, body.code_verifier)
    if pair is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Código de entrega inválido o expirado"
        )
    return ApiResponse.ok(dump(pair))


def _closing_popup_html(message: str) -> str:
    return (
        f"<html><body><h3>{message}</h3>"
        "<script>setTimeout(()=>window.close(),3000);</script></body></html>"
    )


def _delivery_popup_html(payload: dict) -> str:
    """postMessage aditivo al opener — ver nota al inicio de esta sección."""
    return (
        "<html><body><p>Login completado. Puede cerrar esta ventana.</p>"
        "<script>"
        f"if (window.opener) {{ window.opener.postMessage({json.dumps(payload)}, '*'); }}"
        "window.close();"
        "</script></body></html>"
    )


@router.get("/azure/callback", response_model=None)
def azure_callback(
    request: Request, code: str, state: str, session: Session = Depends(get_db_session)
) -> HTMLResponse | RedirectResponse:
    settings = get_settings().azure_ad
    try:
        if settings.secure_token_delivery:
            pair, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
                session,
                code,
                state,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("User-Agent"),
            )
        else:
            pair = azure_auth_service.handle_callback(
                session,
                code,
                state,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("User-Agent"),
            )
            delivery_code = None
    except PermissionError as exc:
        return HTMLResponse(_closing_popup_html(f"Acceso no autorizado: {exc}"))
    except Exception:
        # Nunca se expone str(exc) al popup (mismo no-negociable que
        # UnhandledExceptionMiddleware), pero SÍ hay que loggear el traceback real —
        # antes este except lo tragaba en silencio, sin dejar ningún rastro server-side.
        logger.exception("Error no controlado en azure_callback")
        return HTMLResponse(
            _closing_popup_html(
                "Ocurrió un error inesperado. Cierra esta ventana e intenta de nuevo."
            )
        )

    if pair is None:
        return HTMLResponse(
            _closing_popup_html("No existe una cuenta local asociada a este correo institucional.")
        )

    if delivery_code is not None:
        if settings.frontend_relay_url:
            # delivery_code es base64 estandar (+, /, = incluidos, no url-safe):
            # sin quote(), "+" se decodifica como espacio via URLSearchParams en
            # el frontend y corrompe el codigo antes del exchange.
            return RedirectResponse(
                f"{settings.frontend_relay_url}?deliveryCode={quote(delivery_code, safe='')}",
                status_code=302,
            )
        # Fallback si no hay AZURE_AD__FRONTEND_RELAY_URL configurado: sigue
        # funcionando para pruebas que no pasan por un IdP con COOP estricto
        # (ver nota en _delivery_popup_html), pero NO para Microsoft real —
        # window.opener ya no sobrevive esa navegación.
        logger.warning(
            "AZURE_AD__FRONTEND_RELAY_URL no configurado — usando postMessage directo, "
            "que no funciona tras un login real de Microsoft (ver COOP)."
        )
        return HTMLResponse(
            _delivery_popup_html({"type": "AZURE_LOGIN_DELIVERY", "deliveryCode": delivery_code})
        )
    return HTMLResponse(
        _delivery_popup_html(
            {
                "type": "AZURE_LOGIN_DELIVERY",
                "pair": {"accessToken": pair.access_token, "refreshToken": pair.refresh_token},
            }
        )
    )
