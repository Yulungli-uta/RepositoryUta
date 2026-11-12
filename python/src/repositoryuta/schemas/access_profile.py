from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class AccessProfileCreate(ApiModel):
    name: str
    description: str | None = None


class AccessProfileUpdate(ApiModel):
    description: str | None = None
    is_active: bool | None = None


class AccessProfileRead(ApiModel):
    id: int
    name: str
    description: str | None
    is_active: bool
    created_at: datetime
    is_deleted: bool


class AccessProfileRoleRead(ApiModel):
    access_profile_id: int
    role_id: int


class AccessProfileRoleCreate(ApiModel):
    access_profile_id: int
    role_id: int


class AccessProfileRoleUpdate(ApiModel):
    """No-op: espejo de UpdateAccessProfileRoleDto (sin campos) — no hay PUT
    para esta entidad en .NET, solo existe para completar el tipo generico."""


class UserAccessProfileCreate(ApiModel):
    """Espejo de AssignAccessProfileDto — asignar un perfil a un usuario."""

    user_id: UUID
    access_profile_id: int
    assigned_by: str | None = None
