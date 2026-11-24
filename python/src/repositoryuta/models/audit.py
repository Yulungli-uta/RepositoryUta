from datetime import datetime
from typing import ClassVar
from uuid import UUID

from sqlalchemy import Index, Integer, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, BigIntegerPk


class AuditLog(Base):
    """auth.tbl_AuditLog. Solo insercion (AuditService.LogAsync)."""

    __tablename__ = "tbl_AuditLog"
    __table_args__ = (
        Index("ix_tbl_AuditLog_UserId_Timestamp", "UserId", "Timestamp"),
        Index("ix_tbl_AuditLog_Module_Timestamp", "Module", "Timestamp"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column("UserId", Uuid)
    action: Mapped[str] = mapped_column("Action", String(100), nullable=False)
    module: Mapped[str] = mapped_column("Module", String(100), nullable=False)
    entity_id: Mapped[str | None] = mapped_column("EntityId", Text)
    old_values: Mapped[str | None] = mapped_column("OldValues", Text)
    new_values: Mapped[str | None] = mapped_column("NewValues", Text)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String(64))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(400))
    timestamp: Mapped[datetime] = mapped_column(
        "Timestamp", server_default=text("SYSUTCDATETIME()")
    )


class LoginHistory(Base):
    """auth.tbl_LoginHistory. Solo insercion (AuthRepository.InsertLoginAsync)."""

    __tablename__ = "tbl_LoginHistory"
    __table_args__ = (
        Index("ix_tbl_LoginHistory_UserId_LoginDateTime", "UserId", "LoginDateTime"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID | None] = mapped_column("UserId", Uuid)
    login_date_time: Mapped[datetime] = mapped_column(
        "LoginDateTime", server_default=text("SYSUTCDATETIME()")
    )
    login_type: Mapped[str] = mapped_column("LoginType", String(16), nullable=False)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String(64))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(400))
    device_info: Mapped[str | None] = mapped_column("DeviceInfo", String(300))
    location_info: Mapped[str | None] = mapped_column("LocationInfo", String(200))
    login_status: Mapped[str] = mapped_column("LoginStatus", String(16), nullable=False)
    failure_reason: Mapped[str | None] = mapped_column("FailureReason", Text)
    session_id: Mapped[UUID | None] = mapped_column("SessionId", Uuid)


class RoleChangeHistory(Base):
    """auth.tbl_RoleChangeHistory. Solo insercion."""

    __tablename__ = "tbl_RoleChangeHistory"
    __table_args__ = (
        Index("ix_tbl_RoleChangeHistory_UserId", "UserId"),
        Index("ix_tbl_RoleChangeHistory_RoleId", "RoleId"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    role_id: Mapped[int] = mapped_column("RoleId", Integer, nullable=False)
    change_type: Mapped[str] = mapped_column(
        "ChangeType", String(16), nullable=False, default="Assigned"
    )
    changed_by: Mapped[str] = mapped_column("ChangedBy", String(320), nullable=False)
    change_reason: Mapped[str | None] = mapped_column("ChangeReason", String(300))
    previous_value: Mapped[str | None] = mapped_column("PreviousValue", Text)
    new_value: Mapped[str | None] = mapped_column("NewValue", Text)
    effective_from: Mapped[datetime | None] = mapped_column("EffectiveFrom")
    effective_to: Mapped[datetime | None] = mapped_column("EffectiveTo")
    change_date_time: Mapped[datetime] = mapped_column(
        "ChangeDateTime", server_default=text("SYSUTCDATETIME()")
    )
    approval_required: Mapped[bool] = mapped_column("ApprovalRequired", default=False)
    approved_by: Mapped[str | None] = mapped_column("ApprovedBy", Text)
    approval_date_time: Mapped[datetime | None] = mapped_column("ApprovalDateTime")


class PermissionChangeHistory(Base):
    """auth.tbl_PermissionChangeHistory. Solo insercion."""

    __tablename__ = "tbl_PermissionChangeHistory"
    __table_args__ = (
        Index("ix_tbl_PermissionChangeHistory_RoleId", "RoleId"),
        Index("ix_tbl_PermissionChangeHistory_PermissionId", "PermissionId"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    role_id: Mapped[int] = mapped_column("RoleId", Integer, nullable=False)
    permission_id: Mapped[int] = mapped_column("PermissionId", Integer, nullable=False)
    change_type: Mapped[str] = mapped_column(
        "ChangeType", String(16), nullable=False, default="Added"
    )
    changed_by: Mapped[str] = mapped_column("ChangedBy", String(320), nullable=False)
    change_reason: Mapped[str | None] = mapped_column("ChangeReason", String(300))
    change_date_time: Mapped[datetime] = mapped_column(
        "ChangeDateTime", server_default=text("SYSUTCDATETIME()")
    )
    affected_users_count: Mapped[int] = mapped_column("AffectedUsersCount", default=0)


class _SyncLogColumns:
    """Columnas identicas de AzureSyncLog/HRSyncLog (mismo shape en el .NET,
    duplicado alla en dos clases separadas — se replica igual, sin fusionar
    las 2 tablas reales en una sola)."""

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    sync_date: Mapped[datetime] = mapped_column(
        "SyncDate", server_default=text("SYSUTCDATETIME()")
    )
    records_processed: Mapped[int] = mapped_column("RecordsProcessed", default=0)
    new_users: Mapped[int] = mapped_column("NewUsers", default=0)
    updated_users: Mapped[int] = mapped_column("UpdatedUsers", default=0)
    errors: Mapped[int] = mapped_column("Errors", default=0)
    details: Mapped[str | None] = mapped_column("Details", Text)
    sync_type: Mapped[str] = mapped_column(
        "SyncType", String(16), default="Auto", server_default="Auto"
    )


class AzureSyncLog(Base, _SyncLogColumns):
    __tablename__ = "tbl_AzureSyncLog"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}


class HRSyncLog(Base, _SyncLogColumns):
    __tablename__ = "tbl_HRSyncLog"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}
