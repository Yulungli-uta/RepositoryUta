from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from repositoryuta.config import get_settings
from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import require_roles
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.local_ad import (
    ChangeLocalAdUserPasswordRequest,
    CreateLocalAdGroupRequest,
    CreateLocalAdUserRequest,
    EntraSyncResultRead,
    LocalAdAuthRequest,
    LocalAdAuthResponse,
    LocalAdGroupResponse,
    LocalAdUserResponse,
    LocalAdUserWithSyncResponse,
    UpdateLocalAdUserRequest,
)
from repositoryuta.services import azure_management_service, local_ad_service

# Espejo de LocalAdController.cs.
router = APIRouter(prefix="/api/local-ad", tags=["local-ad"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _expected_domain() -> str:
    base_dn = get_settings().local_ad.base_dn or ""
    parts = [p.strip()[3:] for p in base_dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def _map_user(user: local_ad_service.DirectoryUser) -> LocalAdUserResponse:
    return LocalAdUserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        given_name=user.given_name,
        surname=user.surname,
        job_title=user.job_title,
        department=user.department,
        account_enabled=user.is_enabled,
    )


def _map_group(group: local_ad_service.DirectoryGroup) -> LocalAdGroupResponse:
    return LocalAdGroupResponse(
        id=group.id, name=group.name, description=group.description, email=group.email
    )


def _map_sync(sync: azure_management_service.EntraSyncResult) -> EntraSyncResultRead:
    return EntraSyncResultRead(
        status=sync.status.value,
        account_enabled=sync.account_enabled,
        azure_object_id=sync.azure_object_id,
        message=sync.message,
    )


def _map_user_with_sync(
    user: local_ad_service.DirectoryUser, sync: azure_management_service.EntraSyncResult
) -> LocalAdUserWithSyncResponse:
    return LocalAdUserWithSyncResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        given_name=user.given_name,
        surname=user.surname,
        job_title=user.job_title,
        department=user.department,
        account_enabled=user.is_enabled,
        entra_sync=_map_sync(sync),
    )


def _not_found(what: str, identifier: str) -> HTTPException:
    detail = f"{what} '{identifier}' no encontrado en AD"
    return HTTPException(status.HTTP_404_NOT_FOUND, detail=detail)


# ── Autenticacion ─────────────────────────────────────────────────────────────


@router.post("/authenticate")
def authenticate(dto: LocalAdAuthRequest) -> ApiResponse:
    """[AllowAnonymous]."""
    if not dto.username.strip() or not dto.password.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Usuario y contraseña son requeridos"
        )

    result = local_ad_service.authenticate_user(dto.username, dto.password)
    if not result.success:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

    response = LocalAdAuthResponse(
        success=True, email=result.email, display_name=result.display_name
    )
    return ApiResponse.ok(dump(response), "Autenticación exitosa")


# ── Usuarios ──────────────────────────────────────────────────────────────────


@router.get("/users")
def list_users(
    page: int = 1,
    pageSize: int = 50,
    filter: str | None = None,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    users = local_ad_service.list_users(page, pageSize, filter)
    mapped = [dump(_map_user(u)) for u in users]
    return ApiResponse.ok(
        {"items": mapped, "page": page, "pageSize": pageSize, "totalCount": len(mapped)}
    )


@router.get("/users/by-email/{email}")
def get_user_by_email(
    email: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    user = local_ad_service.find_user_by_email(email)
    if user is None:
        raise _not_found("Usuario", email)
    return ApiResponse.ok(dump(_map_user(user)))


@router.get("/users/{user_id}/groups")
def get_user_groups(
    user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    groups = local_ad_service.get_user_groups(user_id)
    return ApiResponse.ok([dump(_map_group(g)) for g in groups], f"{len(groups)} grupo(s)")


@router.get("/users/{user_id}/groups/{group_id}")
def is_user_in_group(
    user_id: str, group_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    is_member = local_ad_service.is_user_in_group(group_id, user_id)
    message = "El usuario pertenece al grupo" if is_member else "El usuario no pertenece al grupo"
    return ApiResponse.ok({"isMember": is_member}, message)


@router.get("/users/{user_id}/entra-sync")
def check_entra_sync(
    user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    user = local_ad_service.get_user(user_id)
    if user is None:
        raise _not_found("Usuario", user_id)
    sync = azure_management_service.check_user_entra_sync(user.email)
    return ApiResponse.ok(dump(_map_sync(sync)), sync.message)


@router.get("/users/{user_id}")
def get_user(user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))) -> ApiResponse:
    user = local_ad_service.get_user(user_id)
    if user is None:
        raise _not_found("Usuario", user_id)
    return ApiResponse.ok(dump(_map_user(user)))


@router.post("/users")
def create_user(
    dto: CreateLocalAdUserRequest, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    if not dto.email.strip() or not dto.display_name.strip() or not dto.initial_password.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Email, DisplayName e InitialPassword son requeridos",
        )
    if not dto.given_name or not dto.given_name.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="El nombre (GivenName) es requerido para crear el usuario en AD",
        )
    if not dto.surname or not dto.surname.strip():
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="El apellido (Surname) es requerido para crear el usuario en AD",
        )

    expected_domain = _expected_domain()
    if expected_domain and not dto.email.lower().endswith(f"@{expected_domain.lower()}"):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"El correo debe usar el dominio institucional: @{expected_domain}",
        )

    new_user = local_ad_service.DirectoryUser(
        id="",
        email=dto.email,
        display_name=dto.display_name,
        given_name=dto.given_name,
        surname=dto.surname,
        job_title=dto.job_title,
        department=dto.department,
        is_enabled=dto.account_enabled,
    )
    target_ou = dto.target_ou or get_settings().local_ad.funcionarios_activos_ou or ""
    created = local_ad_service.create_user(
        new_user, dto.initial_password, target_ou, dto.force_password_change
    )
    sync = azure_management_service.check_user_entra_sync(created.email)
    return ApiResponse.ok(
        dump(_map_user_with_sync(created, sync)),
        "Usuario creado en AD. Estado de sincronización con Microsoft Entra adjunto.",
    )


@router.put("/users/{user_id}")
def update_user(
    user_id: str,
    dto: UpdateLocalAdUserRequest,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    existing = local_ad_service.get_user(user_id)
    if existing is None:
        raise _not_found("Usuario", user_id)

    updated = local_ad_service.DirectoryUser(
        id=existing.id,
        email=existing.email,
        display_name=dto.display_name or existing.display_name,
        given_name=dto.given_name or existing.given_name,
        surname=dto.surname or existing.surname,
        job_title=dto.job_title or existing.job_title,
        department=dto.department or existing.department,
        is_enabled=existing.is_enabled,
    )
    result = local_ad_service.update_user(user_id, updated)
    return ApiResponse.ok(dump(_map_user(result)), "Usuario actualizado")


@router.post("/users/{user_id}/enable")
def enable_user(
    user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    existing = local_ad_service.get_user(user_id)
    if existing is None:
        raise _not_found("Usuario", user_id)

    local_ad_service.set_user_enabled(user_id, True)
    sync = azure_management_service.check_user_entra_sync(existing.email)
    return ApiResponse.ok(
        {"sync": dump(_map_sync(sync))},
        "Usuario habilitado en AD. Verifique el estado de sincronización con Microsoft Entra.",
    )


@router.post("/users/{user_id}/disable")
def disable_user(
    user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    existing = local_ad_service.get_user(user_id)
    if existing is None:
        raise _not_found("Usuario", user_id)

    local_ad_service.set_user_enabled(user_id, False)
    sync = azure_management_service.check_user_entra_sync(existing.email)
    return ApiResponse.ok(
        {"sync": dump(_map_sync(sync))},
        "Usuario deshabilitado en AD. Para completar el bloqueo en Office 365 se requiere "
        "sincronización con Entra Connect.",
    )


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    existing = local_ad_service.get_user(user_id)
    if existing is None:
        raise _not_found("Usuario", user_id)

    upn = existing.email
    local_ad_service.delete_user(user_id)
    sync = azure_management_service.check_user_entra_sync(upn)
    return ApiResponse.ok(
        {"sync": dump(_map_sync(sync))},
        "Usuario eliminado de AD. La eliminación en Microsoft Entra se completará tras la "
        "sincronización con Entra Connect.",
    )


@router.post("/users/{user_id}/change-password")
def change_user_password(
    user_id: str,
    dto: ChangeLocalAdUserPasswordRequest,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    if not dto.new_password.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La nueva contraseña es requerida")

    existing = local_ad_service.get_user(user_id)
    if existing is None:
        raise _not_found("Usuario", user_id)

    local_ad_service.change_user_password(user_id, dto.new_password, dto.force_password_change)
    return ApiResponse.ok(message="Contraseña restablecida exitosamente")


# ── Grupos ────────────────────────────────────────────────────────────────────


@router.get("/groups")
def list_groups(
    page: int = 1,
    pageSize: int = 50,
    filter: str | None = None,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    groups = local_ad_service.list_groups(page, pageSize, filter)
    mapped = [dump(_map_group(g)) for g in groups]
    return ApiResponse.ok(
        {"items": mapped, "page": page, "pageSize": pageSize, "totalCount": len(mapped)}
    )


@router.get("/groups/{group_id}/members")
def get_group_members(
    group_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    """Espejo EXACTO de LocalAdController.GetGroupMembers — incluye un bug real
    del .NET: llama a GetUserGroupsAsync(groupId) tratando el groupId como si
    fuera un userId, en vez de listar los miembros reales del grupo. Esto NO
    devuelve los usuarios del grupo; busca grupos que anidan a `group_id` como
    miembro (member={dn de group_id}) — casi siempre vacío en la práctica. No
    se corrige sin aprobación explícita (regla de fidelidad de Fase 0)."""
    group = local_ad_service.get_group(group_id)
    if group is None:
        raise _not_found("Grupo", group_id)
    members = local_ad_service.get_user_groups(group_id)
    return ApiResponse.ok([dump(_map_group(g)) for g in members])


@router.get("/groups/{group_id}")
def get_group(
    group_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    group = local_ad_service.get_group(group_id)
    if group is None:
        raise _not_found("Grupo", group_id)
    return ApiResponse.ok(dump(_map_group(group)))


@router.post("/groups")
def create_group(
    dto: CreateLocalAdGroupRequest, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    if not dto.group_name.strip():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="El nombre del grupo es requerido")

    created = local_ad_service.create_group(dto.group_name, dto.description)
    return ApiResponse.ok(dump(_map_group(created)), "Grupo creado en AD")


@router.post("/groups/{group_id}/members/{user_id}")
def add_user_to_group(
    group_id: str, user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    local_ad_service.add_user_to_group(group_id, user_id)
    return ApiResponse.ok(message="Usuario agregado al grupo")


@router.delete("/groups/{group_id}/members/{user_id}")
def remove_user_from_group(
    group_id: str, user_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    local_ad_service.remove_user_from_group(group_id, user_id)
    return ApiResponse.ok(message="Usuario removido del grupo")
