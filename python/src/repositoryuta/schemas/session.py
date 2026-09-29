from datetime import datetime
from uuid import UUID

from pydantic import Field

from repositoryuta.core.schema_base import ApiModel


class UserSessionCreate(ApiModel):
    user_id: UUID
    access_token: str
    refresh_token: str
    expires_at: datetime
    is_active: bool | None = None
    device_info: str | None = None
    ip_address: str | None = None
    status: str | None = None


class UserSessionUpdate(ApiModel):
    is_active: bool | None = None
    expires_at: datetime | None = None
    status: str | None = None


class UserSessionRead(ApiModel):
    """Espejo EXACTO de lo que SessionsController.cs devuelve (la entidad
    completa vía ApiResponse.Ok(entity), incluidos access_token/refresh_token
    en claro) — controller de solo lectura restringido a Administrador/R_DITIC,
    sin DTO acotado en el .NET real."""

    session_id: UUID
    user_id: UUID
    access_token: str
    refresh_token: str
    expires_at: datetime
    is_active: bool
    device_info: str | None
    ip_address: str | None
    created_at: datetime
    status: str
    browser_id: str | None
    user_agent: str | None
    last_activity_at: datetime | None
    revoked_at: datetime | None
    revoked_by: str | None


class FailedAttemptCreate(ApiModel):
    user_email: str
    ip_address: str | None = None
    user_agent: str | None = None
    reason: str | None = None
    window_bucket: datetime | None = None


class FailedAttemptUpdate(ApiModel):
    reason: str | None = None


class FailedAttemptRead(ApiModel):
    id: int
    user_email: str
    attempted_at: datetime
    ip_address: str | None
    user_agent: str | None
    reason: str | None
    window_bucket: datetime | None


class ActiveSessionRead(ApiModel):
    """Espejo EXACTO de ActiveSessionDto (Models/DTOs/SessionManagementDtos.cs)
    — a diferencia de VwActiveSession (models/views.py), el DTO real NO expone
    ws_connection_id, y colapsa ws_is_active a un bool `is_websocket_connected`
    (`s.WsIsActive == true` en el .NET). Se construye a mano en
    services/session_management_service.py, no via model_validate directo
    sobre la fila de la vista.
    """

    session_id: UUID
    user_id: UUID
    email: str
    display_name: str | None
    user_type: str
    ip_address: str | None
    user_agent: str | None
    browser_id: str | None
    login_at: datetime
    last_activity_at: datetime | None
    expires_at: datetime
    status: str
    # Alias explicito: pydantic.to_camel no puede saber que "WebSocket" es una
    # sola palabra compuesta con mayuscula interna (IsWebSocketConnected en el
    # .NET real) — sin esto, saldria "isWebsocketConnected" y rompe el
    # contrato con HrFrontend/HrBackend.
    is_websocket_connected: bool = Field(alias="isWebSocketConnected")
    ws_last_ping: datetime | None = None


class RevokeSessionResult(ApiModel):
    """Espejo de RevokeSessionResultDto."""

    session_id: UUID
    was_notified: bool
    message: str
