from datetime import datetime
from uuid import UUID

from pydantic import Field

from repositoryuta.core.schema_base import ApiModel


class ApplicationCreate(ApiModel):
    name: str
    client_id: str
    client_secret: str
    description: str | None = None
    token_expiration_min: int | None = None
    refresh_token_exp_days: int | None = None
    allowed_origins: str | None = None


class ApplicationUpdate(ApiModel):
    name: str | None = None
    description: str | None = None
    is_active: bool | None = None
    token_expiration_min: int | None = None
    refresh_token_exp_days: int | None = None
    allowed_origins: str | None = None


class LegacyAuthLogCreate(ApiModel):
    application_id: UUID
    user_id: UUID | None = None
    user_email: str
    auth_result: str
    failure_reason: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    response_time: int | None = None
    response_time: int | None = None


class ActiveApiClientRead(ApiModel):
    """Espejo de ActiveApiClientDto — proyeccion de auth.vw_ActiveApiClients."""

    id: UUID
    name: str
    client_id: str
    description: str | None
    is_active: bool
    created_at: datetime
    created_by: str | None
    last_used_at: datetime | None
    secret_rotated_at: datetime | None
    secret_rotated_by: str | None
    suspended_at: datetime | None
    suspended_by: str | None
    # Alias explicito: pydantic.to_camel trata "24h" como una palabra nueva y
    # la titlecasea a "24H" (CallsLast24h en el .NET real es "callsLast24h" —
    # solo se minuscula la primera letra). Sin esto rompe el contrato con
    # HrFrontend/HrBackend.
    calls_last_24h: int = Field(alias="callsLast24h")
    last_ip_address: str | None
    last_user_agent: str | None


class ToggleClientResult(ApiModel):
    """Espejo de ToggleClientResultDto."""

    application_id: UUID
    client_id: str
    is_active: bool
    message: str


class RotateSecretResult(ApiModel):
    """Espejo de RotateSecretResultDto. new_client_secret viaja en texto plano
    una sola vez — nunca se vuelve a poder consultar."""

    application_id: UUID
    client_id: str
    new_client_secret: str
    rotated_at: datetime
