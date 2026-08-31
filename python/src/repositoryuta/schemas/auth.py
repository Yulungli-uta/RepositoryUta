from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class LoginRequest(ApiModel):
    email: str
    password: str


class RefreshRequest(ApiModel):
    refresh_token: str


class TokenPair(ApiModel):
    access_token: str
    refresh_token: str


class AzureAuthUrlRequest(ApiModel):
    client_id: str | None = None
    browser_id: str | None = None
    code_challenge: str | None = None


class AzureExchangeRequest(ApiModel):
    """Intercambio PKCE (RFC 7636): canjea un deliveryCode de un solo uso por el
    par de tokens real, demostrando posesion del codeVerifier que nunca salio de
    la pestana que inicio el login con Office 365."""

    delivery_code: str
    code_verifier: str


class ValidateTokenRequest(ApiModel):
    token: str
    client_id: str | None = None


class ValidateTokenResponse(ApiModel):
    is_valid: bool
    token_type: str
    expires_at: datetime | None = None
    user_id: UUID | None = None
    session_id: UUID | None = None
    message: str | None = None
    email: str


class MeResponse(ApiModel):
    """Espejo del anonimo que retorna AuthService.MeAsync."""

    id: UUID
    email: str
    personnel_email: str | None
    display_name: str | None
    user_type: str
    last_login: datetime | None
    roles: list[str]
    action_permissions: list[str]
    profiles: list[str]
