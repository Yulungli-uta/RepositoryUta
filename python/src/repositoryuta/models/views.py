from datetime import datetime
from typing import ClassVar
from uuid import UUID

from sqlalchemy import Boolean, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base

# Las 4 vistas son de solo lectura (HasNoKey() en .NET) — SQLAlchemy ORM SI
# exige una primary_key para el identity map, a diferencia de EF Core. Se usa
# la combinacion de columnas que es naturalmente unica en cada vista (nunca se
# hace INSERT/UPDATE/DELETE contra estos modelos).


class VwUserRole(Base):
    """dbo.vw_UserRoles — OJO: schema "dbo", no "auth" (unico caso distinto en
    todo el esquema). Consumida por UserPermissionRepository.GetUserRolesAsync
    / GetUserRoleIdsAsync."""

    __tablename__ = "vw_UserRoles"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "dbo"}

    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, primary_key=True)
    role_id: Mapped[int] = mapped_column("RoleId", Integer, primary_key=True)
    email: Mapped[str] = mapped_column("Email", String)
    display_name: Mapped[str] = mapped_column("DisplayName", String)
    user_type: Mapped[str] = mapped_column("UserType", String)
    role_name: Mapped[str] = mapped_column("RoleName", String)
    role_description: Mapped[str | None] = mapped_column("RoleDescription", String)
    assigned_at: Mapped[datetime | None] = mapped_column("AssignedAt")
    expires_at: Mapped[datetime | None] = mapped_column("ExpiresAt")
    assigned_by: Mapped[str | None] = mapped_column("AssignedBy", String)


class VwRoleMenuItem(Base):
    """dbo.vw_RoleMenuItems (schema "dbo", igual que vw_UserRoles). Consumida
    por UserPermissionRepository.GetUserMenuItemsAsync."""

    __tablename__ = "vw_RoleMenuItems"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "dbo"}

    role_id: Mapped[int] = mapped_column("RoleId", Integer, primary_key=True)
    menu_item_id: Mapped[int] = mapped_column("MenuItemId", Integer, primary_key=True)
    role_name: Mapped[str] = mapped_column("RoleName", String)
    menu_item_name: Mapped[str] = mapped_column("MenuItemName", String)
    url: Mapped[str | None] = mapped_column("Url", String)
    icon: Mapped[str | None] = mapped_column("Icon", String)
    parent_id: Mapped[int | None] = mapped_column("ParentId", Integer)
    order: Mapped[int] = mapped_column("Order", Integer)
    is_visible: Mapped[bool] = mapped_column("IsVisible", Boolean)
    role_specific_visibility: Mapped[bool] = mapped_column("RoleSpecificVisibility", Boolean)


class VwActiveSession(Base):
    """auth.vw_ActiveSessions — sesiones activas con su conexion WS asociada.
    Consumida por SessionManagementService."""

    __tablename__ = "vw_ActiveSessions"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    session_id: Mapped[UUID] = mapped_column("SessionId", Uuid, primary_key=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid)
    email: Mapped[str] = mapped_column("Email", String)
    display_name: Mapped[str | None] = mapped_column("DisplayName", String)
    user_type: Mapped[str] = mapped_column("UserType", String)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String)
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String)
    browser_id: Mapped[str | None] = mapped_column("BrowserId", String)
    login_at: Mapped[datetime] = mapped_column("LoginAt")
    last_activity_at: Mapped[datetime | None] = mapped_column("LastActivityAt")
    expires_at: Mapped[datetime] = mapped_column("ExpiresAt")
    status: Mapped[str] = mapped_column("Status", String)
    ws_connection_id: Mapped[str | None] = mapped_column("WsConnectionId", String)
    ws_last_ping: Mapped[datetime | None] = mapped_column("WsLastPing")
    ws_is_active: Mapped[bool | None] = mapped_column("WsIsActive", Boolean)


class VwActiveApiClient(Base):
    """auth.vw_ActiveApiClients — clientes API con estadisticas de uso.
    Consumida por SessionManagementService."""

    __tablename__ = "vw_ActiveApiClients"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True)
    name: Mapped[str] = mapped_column("Name", String)
    client_id: Mapped[str] = mapped_column("ClientId", String)
    description: Mapped[str | None] = mapped_column("Description", String)
    is_active: Mapped[bool] = mapped_column("IsActive", Boolean)
    created_at: Mapped[datetime] = mapped_column("CreatedAt")
    created_by: Mapped[str | None] = mapped_column("CreatedBy", String)
    last_used_at: Mapped[datetime | None] = mapped_column("LastUsedAt")
    secret_rotated_at: Mapped[datetime | None] = mapped_column("SecretRotatedAt")
    secret_rotated_by: Mapped[str | None] = mapped_column("SecretRotatedBy", String)
    suspended_at: Mapped[datetime | None] = mapped_column("SuspendedAt")
    suspended_by: Mapped[str | None] = mapped_column("SuspendedBy", String)
    calls_last_24h: Mapped[int] = mapped_column("CallsLast24h", Integer)
    last_ip_address: Mapped[str | None] = mapped_column("LastIpAddress", String)
    last_user_agent: Mapped[str | None] = mapped_column("LastUserAgent", String)
