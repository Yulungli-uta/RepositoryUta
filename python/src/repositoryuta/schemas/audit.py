from datetime import datetime
from uuid import UUID

from pydantic import Field

from repositoryuta.core.schema_base import ApiModel


class AuditLogCreate(ApiModel):
    user_id: UUID | None = None
    action: str
    module: str
    entity_id: str | None = None
    old_values: str | None = None
    new_values: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None


class AuditLogRead(ApiModel):
    id: int
    user_id: UUID | None
    action: str
    module: str
    entity_id: str | None
    old_values: str | None
    new_values: str | None
    ip_address: str | None
    user_agent: str | None
    timestamp: datetime


class LoginHistoryCreate(ApiModel):
    user_id: UUID | None = None
    login_type: str
    login_status: str
    ip_address: str | None = None
    user_agent: str | None = None
    device_info: str | None = None
    location_info: str | None = None
    session_id: UUID | None = None
    failure_reason: str | None = None


class LoginHistoryRead(ApiModel):
    id: int
    user_id: UUID | None
    login_date_time: datetime
    login_type: str
    ip_address: str | None
    user_agent: str | None
    device_info: str | None
    location_info: str | None
    session_id: UUID | None
    login_status: str
    failure_reason: str | None


class RoleChangeHistoryCreate(ApiModel):
    user_id: UUID
    role_id: int
    change_type: str
    changed_by: str
    change_reason: str | None = None
    previous_value: str | None = None
    new_value: str | None = None
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    approval_required: bool | None = None
    approved_by: str | None = None
    approval_date_time: datetime | None = None


class RoleChangeHistoryUpdate(ApiModel):
    change_reason: str | None = None
    new_value: str | None = None
    effective_to: datetime | None = None
    approval_required: bool | None = None
    approved_by: str | None = None
    approval_date_time: datetime | None = None


class RoleChangeHistoryRead(ApiModel):
    id: int
    user_id: UUID
    role_id: int
    change_type: str
    changed_by: str
    change_reason: str | None
    previous_value: str | None
    new_value: str | None
    effective_from: datetime | None
    effective_to: datetime | None
    change_date_time: datetime
    approval_required: bool
    approved_by: str | None
    approval_date_time: datetime | None


class PermissionChangeHistoryCreate(ApiModel):
    role_id: int
    permission_id: int
    change_type: str
    changed_by: str
    change_reason: str | None = None
    affected_users_count: int | None = None


class PermissionChangeHistoryUpdate(ApiModel):
    change_reason: str | None = None
    affected_users_count: int | None = None


class PermissionChangeHistoryRead(ApiModel):
    id: int
    role_id: int
    permission_id: int
    change_type: str
    changed_by: str
    change_reason: str | None
    change_date_time: datetime
    affected_users_count: int


class SyncLogCreate(ApiModel):
    """Mismo shape para AzureSyncLog y HRSyncLog (idéntico en el .NET, ver
    CreateAzureSyncLogDto/CreateHRSyncLogDto en Models/DTOs/_Dtos.cs)."""

    sync_date: datetime | None = None
    records_processed: int | None = None
    new_users: int | None = None
    updated_users: int | None = None
    errors: int | None = None
    details: str | None = None
    sync_type: str | None = None


class SyncLogUpdate(ApiModel):
    records_processed: int | None = None
    new_users: int | None = None
    updated_users: int | None = None
    errors: int | None = None
    details: str | None = None
    sync_type: str | None = None


class SyncLogRead(ApiModel):
    """Mismo shape para AzureSyncLog y HRSyncLog, igual que SyncLogCreate."""

    id: int
    sync_date: datetime
    records_processed: int
    new_users: int
    updated_users: int
    errors: int
    details: str | None
    sync_type: str


class UserRoleRead(ApiModel):
    """Espejo de UserRoleDto (Models/DTOs/UserPermissionsDto.cs) — proyeccion
    de dbo.vw_UserRoles, no un DTO de escritura."""

    user_id: UUID
    email: str
    display_name: str
    user_type: str
    role_id: int
    role_name: str
    role_description: str | None
    assigned_at: datetime | None
    expires_at: datetime | None
    assigned_by: str | None


class MenuItemRead(ApiModel):
    """Espejo de MenuItemDto — proyeccion de dbo.vw_RoleMenuItems."""

    role_id: int
    role_name: str
    menu_item_id: int
    menu_item_name: str
    url: str | None
    icon: str | None
    parent_id: int | None
    order: int
    is_visible: bool
    role_specific_visibility: bool


class UserPermissionsRead(ApiModel):
    """Espejo de UserPermissionsDto: roles + permisos + menu de un usuario."""

    roles: list[UserRoleRead] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    menu_items: list[MenuItemRead] = Field(default_factory=list)
