import base64
import contextlib
import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta
from uuid import UUID

import msal
import requests
from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.core.ttl_cache import TtlCache
from repositoryuta.repositories.application_repository import ApplicationRepository
from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.session_repository import SessionRepository
from repositoryuta.repositories.user_repository import UserRepository
from repositoryuta.schemas.audit import LoginHistoryCreate
from repositoryuta.schemas.auth import TokenPair
from repositoryuta.services import auth_service, token_service

# Espejo de AzureAuthService.cs: flujo OAuth2/PKCE (RFC 7636) de login
# institucional vía Azure AD, usando MSAL (msal-python, mismo fabricante que
# Microsoft.Identity.Client en .NET). El relay del deliveryCode hacia la
# pestaña original (hoy via SignalR en el .NET) se resuelve en el router con
# window.opener.postMessage, en paralelo — no aqui, este modulo solo produce
# el deliveryCode, igual que CompleteLoginAndIssueDeliveryCodeAsync.

# El .NET real pide ["openid", "profile", "email", "offline_access", "User.Read"]
# explicitos y MSAL.NET lo tolera; MSAL Python (msal 1.31.1) RECHAZA con
# ValueError si le pasas explicito cualquiera de los 3 scopes reservados
# (openid/profile/offline_access) porque los agrega el solo. El permiso
# efectivo pedido a Azure AD queda identico en ambos casos (verificado: la URL
# de autorización final incluye los 5 scopes igual) — es solo una diferencia
# de uso de la API entre MSAL.NET y MSAL Python, no una reduccion de alcance.
_SCOPES = ["email", "User.Read"]
_STATE_TTL_SECONDS = 600
_DELIVERY_CODE_TTL_SECONDS = 300

_state_cache = TtlCache()
_delivery_cache = TtlCache()


def reset_caches() -> None:
    """Solo para pruebas — los caches reales viven todo el ciclo del proceso."""
    _state_cache.clear()
    _delivery_cache.clear()


def _msal_app() -> msal.ConfidentialClientApplication:
    settings = get_settings().azure_ad
    return msal.ConfidentialClientApplication(
        settings.client_id,
        client_credential=settings.client_secret,
        authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
    )


def _validate_client_application(session: Session, client_id: str | None) -> None:
    """Espejo de ValidateClientApplicationAsync."""
    normalized = (client_id or "").strip()
    if not normalized or not ApplicationRepository(session).exists_active_client(normalized):
        raise PermissionError("Aplicación cliente no autorizada.")


def build_auth_url(
    session: Session,
    client_id: str | None,
    browser_id: str | None = None,
    code_challenge: str | None = None,
) -> tuple[str, str]:
    """Espejo de AzureAuthService.BuildAuthUrlAsync."""
    _validate_client_application(session, client_id)
    normalized_client_id = (client_id or "").strip()
    state_id = uuid.uuid4().hex

    state_data = {
        "stateId": state_id,
        "clientId": normalized_client_id,
        "browserId": browser_id,
        "codeChallenge": code_challenge,
        "timestamp": datetime.now().isoformat(),
        "source": "azure_auth",
    }
    state_encoded = base64.b64encode(json.dumps(state_data).encode("utf-8")).decode("ascii")
    _state_cache.set(f"ms_state:{state_id}", state_data, _STATE_TTL_SECONDS)

    settings = get_settings().azure_ad
    url = _msal_app().get_authorization_request_url(
        _SCOPES, state=state_encoded, redirect_uri=settings.redirect_uri
    )
    return url, state_encoded


def _decode_state(state: str) -> dict:
    state_json = base64.b64decode(state).decode("utf-8")
    return json.loads(state_json)


def handle_callback(
    session: Session,
    code: str,
    state: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    device_info: str | None = None,
) -> TokenPair | None:
    """Espejo de AzureAuthService.HandleCallbackAsync. Retorna None si el MFA
    de Azure fue exitoso pero no existe usuario local para ese correo (no es
    un error — el .NET real tampoco lo trata como excepción)."""
    state_data = _decode_state(state)
    state_id = state_data.get("stateId")
    cache_key = f"ms_state:{state_id}"

    if _state_cache.get(cache_key) is None:
        raise PermissionError("State inválido o expirado.")
    _state_cache.remove(cache_key)

    client_id = state_data.get("clientId")
    _validate_client_application(session, client_id)

    settings = get_settings().azure_ad
    result = _msal_app().acquire_token_by_authorization_code(
        code, scopes=_SCOPES, redirect_uri=settings.redirect_uri
    )
    if "access_token" not in result:
        raise RuntimeError(
            result.get("error_description") or "No se pudo obtener el token de Azure AD."
        )

    response = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {result['access_token']}"},
        timeout=10,
    )
    response.raise_for_status()
    me = response.json()
    email = me.get("userPrincipalName") or ""
    azure_id_str = me.get("id")

    allowed_domain = settings.allowed_domain
    if allowed_domain and not email.lower().endswith(f"@{allowed_domain.lower()}"):
        raise PermissionError("Solo se permiten cuentas institucionales.")

    users = UserRepository(session)
    user = users.find_by_email(email)
    if user is None:
        return None

    if azure_id_str:
        with contextlib.suppress(ValueError):
            users.sync_azure_object_id(user.id, UUID(azure_id_str))

    roles = users.get_roles(user.id)
    ad_groups = auth_service.get_ad_groups(email)
    hr_employee_id = users.get_hr_employee_id(user.id)

    access_token = jwt_core.create_user_token(
        str(user.id), email, roles, ad_groups=ad_groups, employee_id=hr_employee_id
    )
    refresh_token = base64.b64encode(secrets.token_bytes(48)).decode("ascii")
    refresh_hash = token_service.hash_token(refresh_token)

    now = datetime.now()
    sessions = SessionRepository(session)
    session_row = sessions.create_session(
        user_id=user.id,
        access_token=access_token,
        refresh_token_hash=refresh_hash,
        expires_at=now + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    users.set_last_login(user.id, now)

    AuditRepository(session).insert_login(
        LoginHistoryCreate(
            user_id=user.id,
            login_type="AzureAD",
            login_status="Success",
            session_id=session_row.session_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
        )
    )
    return TokenPair(access_token=access_token, refresh_token=refresh_token)


def _compute_code_challenge(code_verifier: str) -> str:
    """codeChallenge = base64url(SHA-256(codeVerifier)), RFC 7636."""
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii").replace("+", "-").replace("/", "_").rstrip("=")


def complete_login_and_issue_delivery_code(
    session: Session,
    code: str,
    state: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    device_info: str | None = None,
) -> tuple[TokenPair | None, str | None]:
    """Espejo de CompleteLoginAndIssueDeliveryCodeAsync."""
    code_challenge = None
    try:
        state_data = _decode_state(state)
        code_challenge = state_data.get("codeChallenge")
    except Exception:
        pass  # handle_callback lanzará su propia validación de state abajo.

    pair = handle_callback(session, code, state, ip_address, user_agent, device_info)
    if pair is None:
        return None, None

    if not code_challenge:
        return pair, None

    delivery_code = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    _delivery_cache.set(
        f"delivery:{delivery_code}",
        {"pair": pair, "code_challenge": code_challenge},
        _DELIVERY_CODE_TTL_SECONDS,
    )
    return pair, delivery_code


def exchange_delivery_code(delivery_code: str, code_verifier: str) -> TokenPair | None:
    """Espejo de ExchangeDeliveryCodeAsync: canje de un solo uso, comparación
    en tiempo constante."""
    cache_key = f"delivery:{delivery_code}"
    entry = _delivery_cache.get(cache_key)
    if entry is None:
        return None

    computed = _compute_code_challenge(code_verifier)
    matches = hmac.compare_digest(computed.encode("utf-8"), entry["code_challenge"].encode("utf-8"))
    if not matches:
        return None

    _delivery_cache.remove(cache_key)
    return entry["pair"]
