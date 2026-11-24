from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class RoleCreate(ApiModel):
    name: str
    description: str | None = None
    priority: int = 100


class RoleUpdate(ApiModel):
    description: str | None = None
    is_active: bool | None = None
    priority: int | None = None


class RoleRead(ApiModel):
    id: int
    name: str
    description: str | None
    is_active: bool
    priority: int
    created_at: datetime


class PermissionCreate(ApiModel):
    name: str
    module: str
    action: str
    description: str | None = None
    version: int | None = None


class PermissionUpdate(ApiModel):
    description: str | None = None
    is_deleted: bool | None = None
    version: int | None = None


class PermissionRead(ApiModel):
    id: int
    name: str
    module: str
    action: str
    description: str | None
    version: int


class RolePermissionCreate(ApiModel):
    role_id: int
    permission_id: int
    granted_by: str | None = None


class RolePermissionUpdate(ApiModel):
    granted_by: str | None = None


class RolePermissionRead(ApiModel):
    role_id: int
    permission_id: int
    granted_at: datetime
    granted_by: str | None


class UserRoleCreate(ApiModel):
    user_id: UUID
    role_id: int
    expires_at: datetime | None = None
    assigned_by: str | None = None
    reason: str | None = None
    assigned_via: str | None = None


class UserRoleUpdate(ApiModel):
    expires_at: datetime | None = None
    is_deleted: bool | None = None
    reason: str | None = None


class UserRoleAssignmentRead(ApiModel):
    """Fila cruda de auth.tbl_UserRoles — distinta de UserRoleRead en
    schemas/audit.py, que es la proyeccion de dbo.vw_UserRoles (con datos del
    usuario y del rol ya unidos)."""

    user_id: UUID
    role_id: int
    assigned_at: datetime
    expires_at: datetime | None
    assigned_by: str | None
    reason: str | None
    is_deleted: bool
    assigned_via: str | None


class MenuItemCreate(ApiModel):
    parent_id: int | None = None
    name: str
    url: str | None = None
    icon: str | None = None
    order: int = 0
    module_name: str | None = None
    is_visible: bool | None = None


class MenuItemUpdate(ApiModel):
    parent_id: int | None = None
    name: str | None = None
    url: str | None = None
    icon: str | None = None
    order: int | None = None
    module_name: str | None = None
    is_visible: bool | None = None


class RoleMenuItemCreate(ApiModel):
    role_id: int
    menu_item_id: int
    is_visible: bool | None = None


class RoleMenuItemUpdate(ApiModel):
    is_visible: bool | None = None


class RoleMenuItemRead(ApiModel):
    role_id: int
    menu_item_id: int
    is_visible: bool


class MenuItemRead(ApiModel):
    id: int
    parent_id: int | None
    name: str
    url: str | None
    icon: str | None
    order: int
    is_visible: bool
    module_name: str | None


class MenuNode(ApiModel):
    """Fila resultante de MenuRepository.get_menu_by_user (CTE recursiva, espejo
    de auth.fn_MenuByUser) — forma de lectura, no un DTO de escritura."""

    id: int
    parent_id: int | None
    name: str
    url: str | None
    icon: str | None
    order: int
