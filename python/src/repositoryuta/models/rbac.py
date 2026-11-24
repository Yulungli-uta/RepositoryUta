from datetime import datetime
from typing import ClassVar
from uuid import UUID

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, SoftDeleteMixin


class Role(Base, SoftDeleteMixin):
    """auth.tbl_Roles. Implementa ISoftDeletable en .NET: is_deleted SI se filtra
    automaticamente alla (aqui, a mano, en role_repository.py)."""

    __tablename__ = "tbl_Roles"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column("Name", String(100), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column("Description")
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    priority: Mapped[int] = mapped_column("Priority", Integer, default=100, server_default="100")
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )


class Permission(Base, SoftDeleteMixin):
    """auth.tbl_Permissions. Implementa ISoftDeletable en .NET."""

    __tablename__ = "tbl_Permissions"
    __table_args__ = (
        Index(
            "ix_tbl_Permissions_Name_Module_Action_Version",
            "Name",
            "Module",
            "Action",
            "Version",
            unique=True,
        ),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column("Name", String(150), nullable=False)
    module: Mapped[str] = mapped_column("Module", String(100), nullable=False)
    action: Mapped[str] = mapped_column("Action", String(16), nullable=False, default="Read")
    description: Mapped[str | None] = mapped_column("Description", String(300))
    version: Mapped[int] = mapped_column("Version", Integer, default=1, server_default="1")


class RolePermission(Base):
    """auth.tbl_RolePermissions. PK compuesta (RoleId, PermissionId).

    Sin ISoftDeletable ni columna IsDeleted en .NET: se elimina la fila, no se marca.
    """

    __tablename__ = "tbl_RolePermissions"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    role_id: Mapped[int] = mapped_column(
        "RoleId", ForeignKey("auth.tbl_Roles.Id"), primary_key=True
    )
    permission_id: Mapped[int] = mapped_column(
        "PermissionId", ForeignKey("auth.tbl_Permissions.Id"), primary_key=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        "GrantedAt", server_default=text("SYSUTCDATETIME()")
    )
    granted_by: Mapped[str | None] = mapped_column("GrantedBy", String(320))


class UserRole(Base):
    """auth.tbl_UserRoles. PK compuesta (UserId, RoleId).

    Tiene columna IsDeleted pero NO implementa ISoftDeletable en .NET: no hay
    filtro automatico alla, y UserRepository.GetRolesAsync ya filtra `!IsDeleted`
    a mano. Por eso este modelo NO usa SoftDeleteMixin — el filtrado es
    responsabilidad explicita de cada metodo de repositorio que lo necesite,
    igual que en el .NET real (no una decision de "mejorarlo" aplicando el
    mismo mecanismo que a User/Role/Permission/MenuItem).
    """

    __tablename__ = "tbl_UserRoles"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, primary_key=True)
    role_id: Mapped[int] = mapped_column(
        "RoleId", ForeignKey("auth.tbl_Roles.Id"), primary_key=True
    )
    assigned_at: Mapped[datetime] = mapped_column(
        "AssignedAt", server_default=text("SYSUTCDATETIME()")
    )
    expires_at: Mapped[datetime | None] = mapped_column("ExpiresAt")
    assigned_by: Mapped[str | None] = mapped_column("AssignedBy", String(320))
    reason: Mapped[str | None] = mapped_column("Reason", String(300))
    is_deleted: Mapped[bool] = mapped_column(
        "IsDeleted", Boolean, default=False, server_default=text("0")
    )
    # None/"Direct" = asignacion directa, "Profile:{AccessProfileId}" = heredado
    # de un AccessProfile (ver IAccessProfileAssignmentService, fuera de este corte).
    assigned_via: Mapped[str | None] = mapped_column("AssignedVia", String(150))


class MenuItem(Base, SoftDeleteMixin):
    """auth.tbl_MenuItems. Implementa ISoftDeletable en .NET."""

    __tablename__ = "tbl_MenuItems"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column("Name", String(100), nullable=False)
    url: Mapped[str | None] = mapped_column("Url", String(300))
    icon: Mapped[str | None] = mapped_column("Icon", String(100))
    parent_id: Mapped[int | None] = mapped_column(
        "ParentId", ForeignKey("auth.tbl_MenuItems.Id")
    )
    # "Order" es palabra reservada en T-SQL (se ve como mi.[Order] en fn_MenuByUser);
    # el nombre de columna se preserva igual, SQLAlchemy la cita automaticamente.
    order: Mapped[int] = mapped_column("Order", Integer, default=0, server_default="0")
    is_visible: Mapped[bool] = mapped_column(
        "IsVisible", Boolean, default=True, server_default=text("1")
    )
    module_name: Mapped[str | None] = mapped_column("ModuleName", String(100))


class RoleMenuItem(Base):
    """auth.tbl_RoleMenuItems. PK compuesta (RoleId, MenuItemId)."""

    __tablename__ = "tbl_RoleMenuItems"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    role_id: Mapped[int] = mapped_column(
        "RoleId", ForeignKey("auth.tbl_Roles.Id"), primary_key=True
    )
    menu_item_id: Mapped[int] = mapped_column(
        "MenuItemId", ForeignKey("auth.tbl_MenuItems.Id"), primary_key=True
    )
    is_visible: Mapped[bool] = mapped_column(
        "IsVisible", Boolean, default=True, server_default=text("1")
    )
