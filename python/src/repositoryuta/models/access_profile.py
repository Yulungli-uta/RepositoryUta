from datetime import datetime
from typing import ClassVar
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base


class AccessProfile(Base):
    """auth.tbl_AccessProfiles. Tiene columna IsDeleted pero NO implementa
    ISoftDeletable en .NET (confirmado en _Entities.cs) — sin SoftDeleteMixin
    a proposito, mismo criterio que UserRole (ver models/rbac.py)."""

    __tablename__ = "tbl_AccessProfiles"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column("Name", String(150), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column("Description", String(300))
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )
    is_deleted: Mapped[bool] = mapped_column(
        "IsDeleted", Boolean, default=False, server_default=text("0")
    )


class AccessProfileRole(Base):
    """auth.tbl_AccessProfileRoles. Composicion: que roles agrupa un perfil."""

    __tablename__ = "tbl_AccessProfileRoles"
    __table_args__ = (
        Index("ix_tbl_AccessProfileRoles_RoleId", "RoleId"),
        {"schema": "auth"},
    )

    access_profile_id: Mapped[int] = mapped_column(
        "AccessProfileId", ForeignKey("auth.tbl_AccessProfiles.Id"), primary_key=True
    )
    role_id: Mapped[int] = mapped_column(
        "RoleId", ForeignKey("auth.tbl_Roles.Id"), primary_key=True
    )


class UserAccessProfile(Base):
    """auth.tbl_UserAccessProfiles. Trazabilidad de que perfiles tiene un
    usuario — la autorizacion real siempre pasa por UserRole, esto es
    informativo (ver docstring de AccessProfile en el .NET). Tiene IsDeleted
    pero, igual que AccessProfile, no implementa ISoftDeletable."""

    __tablename__ = "tbl_UserAccessProfiles"
    __table_args__ = (
        Index("ix_tbl_UserAccessProfiles_UserId", "UserId"),
        {"schema": "auth"},
    )

    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, primary_key=True)
    access_profile_id: Mapped[int] = mapped_column(
        "AccessProfileId", ForeignKey("auth.tbl_AccessProfiles.Id"), primary_key=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        "AssignedAt", server_default=text("SYSUTCDATETIME()")
    )
    assigned_by: Mapped[str | None] = mapped_column("AssignedBy", String(320))
    is_deleted: Mapped[bool] = mapped_column(
        "IsDeleted", Boolean, default=False, server_default=text("0")
    )
