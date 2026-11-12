import json
import logging
import uuid
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.core.rate_limit import CLAIM_RATE_LIMIT, LOGIN_RATE_LIMIT, get_client_ip, limiter
from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_current_user_id, get_db_session
from repositoryuta.schemas.auth import (
    AzureAuthUrlRequest,
    AzureClaimRequest,
    AzureExchangeRequest,
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    ValidateTokenRequest,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import ChangePasswordRequest, ChangePasswordWith2FARequest
from repositoryuta.services import auth_service, azure_auth_service, password_change_service

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger(__name__)


_client_ip = get_client_ip


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
        browser_id=body.browser_id,
    )
    if pair is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    return ApiResponse.ok(dump(pair), "Login exitoso")


@router.post("/refresh")
def refresh(body: RefreshRequest, session: Session = Depends(get_db_session)) -> ApiResponse:
    pair = auth_service.refresh(session, body.refresh_token)
    if pair is None:
        # get_db_session hace rollback ante cualquier excepción: se confirma antes para no perder
        # el registro del rechazo ni las revocaciones por reuso de token hechas en esta petición
        session.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido")
    return ApiResponse.ok(dump(pair))


@router.post("/logout")
def logout(body: LogoutRequest, session: Session = Depends(get_db_session)) -> ApiResponse:
    """Idempotente y sin revelar si el token era valido — igual que en .NET,
    LogoutAsync ya se comporta asi (siempre exito salvo body vacio)."""
    if not body.refresh_token or not body.refresh_token.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Refresh token requerido")

    auth_service.logout(session, body.refresh_token, body.reason)
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
    deviceInfo: str | None = None,
    session: Session = Depends(get_db_session),
) -> ApiResponse:
    try:
        url, state = azure_auth_service.build_auth_url(
            session, clientId, browserId, codeChallenge, deviceInfo
        )
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
            session, body.client_id, body.browser_id, body.code_challenge, body.device_info
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


@router.post("/azure/claim")
@limiter.limit(CLAIM_RATE_LIMIT)
def azure_claim(request: Request, body: AzureClaimRequest) -> ApiResponse:
    """Reclamo del login pendiente. Siempre 200: sin nada pendiente (o con el reclamo
    deshabilitado) el dato viene null, sin explicar el motivo."""
    if not body.browser_id.strip() or not body.code_challenge.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="browserId y codeChallenge son requeridos"
        )
    delivery_code = azure_auth_service.claim_pending_delivery(body.browser_id, body.code_challenge)
    return ApiResponse.ok({"deliveryCode": delivery_code})


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


def _closing_popup_html(message: str, reference: str | None = None) -> str:
    ref_html = (
        f'<p style="font-size:12px;color:#666">Código de referencia: <b>{reference}</b></p>'
        if reference
        else ""
    )
    return (
        f"<html><body><h3>{message}</h3>{ref_html}"
        "<script>setTimeout(()=>window.close(),5000);</script></body></html>"
    )


_FAILURE_MESSAGES = {
    azure_auth_service.FAILURE_EXPIRED_ATTEMPT: (
        "El intento de inicio de sesión expiró. Cierra esta ventana e intenta de nuevo."
    ),
    azure_auth_service.FAILURE_NO_ACCESS: (
        "Esta cuenta no tiene acceso habilitado al sistema. "
        "Comunica el código de referencia a DITIC."
    ),
    azure_auth_service.FAILURE_SERVER_ERROR: (
        "Ocurrió un error inesperado. Cierra esta ventana e intenta de nuevo."
    ),
}


def _failure_response(code: str, reference: str) -> HTMLResponse | RedirectResponse:
    """Fallo del callback: con relay configurado la pestana que espera se entera (codigo +
    referencia) y el popup se cierra solo; sin relay se muestra un mensaje generico con la
    referencia. El motivo exacto nunca se expone."""
    relay_url = get_settings().azure_ad.frontend_relay_url
    if relay_url:
        return RedirectResponse(
            f"{relay_url}?loginFailed=1&code={quote(code, safe='')}"
            f"&ref={quote(reference, safe='')}",
            status_code=302,
        )
    message = _FAILURE_MESSAGES.get(
        code, _FAILURE_MESSAGES[azure_auth_service.FAILURE_SERVER_ERROR]
    )
    return HTMLResponse(_closing_popup_html(message, reference))


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
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    session: Session = Depends(get_db_session),
) -> HTMLResponse | RedirectResponse:
    settings = get_settings().azure_ad
    reference = uuid.uuid4().hex[:8].upper()

    # Microsoft redirige aqui SIN "code" y con "error" cuando el usuario pulsa "Atras", cancela o
    # rechaza el acceso: no es una falla del servidor. Antes FastAPI respondia 422 con JSON crudo.
    # No se refleja ni el error ni su descripcion en la pagina.
    if error or not code or not state:
        logger.warning(
            "[AZURE-LOGIN] Inicio de sesion no completado en Microsoft (error=%s)",
            error or "sin_code",
        )
        if settings.frontend_relay_url:
            return RedirectResponse(
                f"{settings.frontend_relay_url}?loginFailed=1&code={azure_auth_service.FAILURE_CANCELLED}",
                status_code=302,
            )
        return HTMLResponse(
            _closing_popup_html(
                "No se completó el inicio de sesión con Microsoft. "
                "Puedes cerrar esta ventana e intentarlo de nuevo."
            )
        )

    try:
        if settings.secure_token_delivery:
            pair, delivery_code = azure_auth_service.complete_login_and_issue_delivery_code(
                session,
                code,
                state,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("User-Agent"),
                device_info=_device_info(request),
                reference=reference,
            )
        else:
            pair = azure_auth_service.handle_callback(
                session,
                code,
                state,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("User-Agent"),
                device_info=_device_info(request),
                reference=reference,
            )
            delivery_code = None
    except PermissionError as exc:
        # El motivo exacto (str(exc)) queda solo en el log; al usuario se le muestra una
        # categoria generica y la referencia. Un rechazo con codigo (AzureLoginRejected) ya
        # quedo en el historial de acceso.
        logger.warning("[AZURE-LOGIN] Callback rechazado (%s). ref=%s", exc, reference)
        code_out = (
            exc.code
            if isinstance(exc, azure_auth_service.AzureLoginRejected)
            else azure_auth_service.FAILURE_NO_ACCESS
        )
        if not isinstance(exc, azure_auth_service.AzureLoginRejected):
            azure_auth_service.record_login_failure(
                session,
                "AZURE_REJECTED",
                None,
                reference,
                _client_ip(request),
                request.headers.get("User-Agent"),
                _device_info(request),
            )
        return _failure_response(code_out, reference)
    except Exception:
        # Nunca se expone str(exc) al popup (mismo no-negociable que
        # UnhandledExceptionMiddleware), pero SÍ hay que loggear el traceback real —
        # antes este except lo tragaba en silencio, sin dejar ningún rastro server-side.
        logger.exception("Error no controlado en azure_callback. ref=%s", reference)
        azure_auth_service.record_login_failure(
            session,
            "AZURE_SERVER_ERROR",
            None,
            reference,
            _client_ip(request),
            request.headers.get("User-Agent"),
            _device_info(request),
        )
        return _failure_response(azure_auth_service.FAILURE_SERVER_ERROR, reference)

    if pair is None:
        # MFA correcto pero sin usuario local (el servicio ya lo registro en el historial).
        return _failure_response(azure_auth_service.FAILURE_NO_ACCESS, reference)

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
