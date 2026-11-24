from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class AppAuthRequest(ApiModel):
    client_id: str
    client_secret: str


class AppAuthResponse(ApiModel):
    """Espejo del record AppAuthResponse (Models/DTOs/_Dtos.cs)."""

    success: bool
    message: str
    access_token: str | None = None
    token_id: UUID | None = None
    expires_at: datetime | None = None
    application_id: UUID | None = None


class LegacyAuthRequest(ApiModel):
    client_id: str
    client_secret: str
    user_email: str
    password: str
    include_permissions: bool | None = None


class LegacyRoleInfo(ApiModel):
    """Espejo del tipo anonimo `new { r.Id, r.Name, r.Description }` en
    AppAuthService.AuthenticateUserLegacyAsync."""

    id: int
    name: str
    description: str | None


class LegacyPermissionInfo(ApiModel):
    """Espejo del tipo anonimo `new { p.Id, p.Name, p.Module, p.Action, p.Description }`."""

    id: int
    name: str
    module: str
    action: str
    description: str | None


class LegacyAuthResponse(ApiModel):
    """Espejo del record LegacyAuthResponse. Roles/Permissions son `object?`
    en el .NET (tipos anonimos) — aqui se tipan concretamente para que el
    contrato JSON sea predecible, sin cambiar la forma real de los datos."""

    success: bool
    message: str
    user_id: UUID | None = None
    email: str | None = None
    display_name: str | None = None
    user_type: str | None = None
    roles: list[LegacyRoleInfo] | None = None
    permissions: list[LegacyPermissionInfo] | None = None


class ApplicationStatsRead(ApiModel):
    """Espejo del tipo anonimo que retorna GetApplicationStatsAsync."""

    application_id: UUID
    name: str
    client_id: str
    is_active: bool
    created_at: datetime
    total_auth_attempts: int
    successful_auths: int
    auths_last_7_days: int
    active_tokens: int
