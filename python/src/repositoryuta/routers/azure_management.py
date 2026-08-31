from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from repositoryuta.core.schema_base import dump
from repositoryuta.routers.dependencies import get_db_session, require_roles
from repositoryuta.schemas.azure_management import (
    CreateAzureGroupRequest,
    CreateAzureUserRequest,
    UpdateAzureGroupRequest,
    UpdateAzureUserRequest,
)
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.services import azure_management_service as azure_mgmt

# Espejo de AzureManagementController.cs.
router = APIRouter(prefix="/api/azure-management", tags=["azure-management"])

_ADMIN_ROLES = ("Administrador", "R_DITIC")


def _bad_request(message: str) -> HTTPException:
    return HTTPException(status.HTTP_400_BAD_REQUEST, detail=message)


# ========== USUARIOS ==========


@router.post("/users")
def create_user(
    dto: CreateAzureUserRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        user = azure_mgmt.create_user_in_azure(session, dto)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(dump(user), "Usuario creado exitosamente en Azure AD")


@router.get("/users/by-email/{email}")
def get_user_by_email(
    email: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    user = azure_mgmt.get_user_by_email_from_azure(email)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado en Azure AD")
    return ApiResponse.ok(dump(user))


@router.get("/users/{azure_object_id}")
def get_user(
    azure_object_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    user = azure_mgmt.get_user_from_azure(azure_object_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado en Azure AD")
    return ApiResponse.ok(dump(user))


@router.put("/users/{azure_object_id}")
def update_user(
    azure_object_id: str,
    dto: UpdateAzureUserRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        user = azure_mgmt.update_user_in_azure(session, azure_object_id, dto)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return ApiResponse.ok(dump(user), "Usuario actualizado exitosamente")


@router.post("/users/{azure_object_id}/enable")
def enable_user(
    azure_object_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.enable_disable_user_in_azure(session, azure_object_id, True)
    if not success:
        raise _bad_request("Error al habilitar usuario")
    return ApiResponse.ok(message="Usuario habilitado exitosamente")


@router.post("/users/{azure_object_id}/disable")
def disable_user(
    azure_object_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.enable_disable_user_in_azure(session, azure_object_id, False)
    if not success:
        raise _bad_request("Error al deshabilitar usuario")
    return ApiResponse.ok(message="Usuario deshabilitado exitosamente")


@router.delete("/users/{azure_object_id}")
def delete_user(
    azure_object_id: str,
    permanent: bool = False,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.delete_user_from_azure(session, azure_object_id, permanent)
    if not success:
        raise _bad_request("Error al eliminar usuario")
    return ApiResponse.ok(message="Usuario eliminado exitosamente")


@router.get("/users")
def list_users(
    page: int = 1,
    pageSize: int = Query(default=50, alias="pageSize"),
    filter: str | None = None,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = azure_mgmt.list_users_from_azure(page, pageSize, filter)
    return ApiResponse.ok(
        {
            "items": [dump(u) for u in result.items],
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


# ========== CONTRASEÑAS ==========


@router.post("/users/{azure_object_id}/reset-password")
def reset_password(
    azure_object_id: str,
    forceChange: bool = Query(default=True, alias="forceChange"),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        temp_password = azure_mgmt.reset_password_in_azure(session, azure_object_id, forceChange)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(
        {
            "temporaryPassword": temp_password,
            "forceChangeNextSignIn": forceChange,
            "message": "Contraseña reseteada exitosamente",
        }
    )


@router.post("/users/{azure_object_id}/change-password")
def change_password(
    azure_object_id: str,
    new_password: str = Body(embed=True, alias="newPassword"),
    force_change_next_sign_in: bool = Body(
        default=False, embed=True, alias="forceChangeNextSignIn"
    ),
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        success = azure_mgmt.change_password_in_azure(
            session, azure_object_id, new_password, force_change_next_sign_in
        )
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    if not success:
        raise _bad_request("Error al cambiar contraseña")
    return ApiResponse.ok(message="Contraseña cambiada exitosamente")


@router.post("/validate-password")
def validate_password(
    password: str = Body(embed=False), _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    result = azure_mgmt.validate_password_policy(password)
    return ApiResponse.ok(dump(result))


@router.get("/generate-password")
def generate_password(_actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))) -> ApiResponse:
    return ApiResponse.ok({"password": azure_mgmt.generate_secure_password()})


# ========== ROLES ==========


@router.get("/azure-roles")
def get_all_azure_roles(_actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))) -> ApiResponse:
    roles = azure_mgmt.get_all_azure_directory_roles()
    return ApiResponse.ok([dump(r) for r in roles])


@router.get("/users/{azure_object_id}/azure-roles")
def get_user_azure_roles(
    azure_object_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    """Espejo de GetUserAzureRoles, SIN las llamadas a GetUserFromAzureAsync y
    GetUserAzureGroupsAsync que el .NET real hace pero nunca usa en la
    respuesta (solo alimentaban un log ya comentado) — evita 2 llamadas Graph
    desperdiciadas, sin cambiar el resultado observable (regla explicita del
    usuario de ahorrar consultas innecesarias)."""
    roles = azure_mgmt.get_user_azure_roles(azure_object_id)
    return ApiResponse.ok([dump(r) for r in roles])


@router.post("/users/{user_id}/azure-roles/{role_id}")
def assign_azure_role(
    user_id: str,
    role_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.assign_azure_role(session, user_id, role_id)
    if not success:
        raise _bad_request("Error al asignar rol")
    return ApiResponse.ok(message="Rol de Azure AD asignado exitosamente")


@router.delete("/users/{user_id}/azure-roles/{role_id}")
def remove_azure_role(
    user_id: str,
    role_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.remove_azure_role(session, user_id, role_id)
    if not success:
        raise _bad_request("Error al remover rol")
    return ApiResponse.ok(message="Rol de Azure AD removido exitosamente")


@router.get("/azure-roles/{role_id}/members")
def get_role_members(
    role_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    members = azure_mgmt.get_role_members(role_id)
    return ApiResponse.ok([dump(m) for m in members])


# ========== GRUPOS ==========


@router.post("/groups")
def create_group(
    dto: CreateAzureGroupRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        group = azure_mgmt.create_group_in_azure(session, dto)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(dump(group), "Grupo creado exitosamente en Azure AD")


@router.get("/groups/{group_id}")
def get_group(
    group_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    group = azure_mgmt.get_group_from_azure(group_id)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Grupo no encontrado en Azure AD")
    return ApiResponse.ok(dump(group))


@router.put("/groups/{group_id}")
def update_group(
    group_id: str,
    dto: UpdateAzureGroupRequest,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    group = azure_mgmt.update_group_in_azure(session, group_id, dto)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Grupo no encontrado")
    return ApiResponse.ok(dump(group), "Grupo actualizado exitosamente")


@router.delete("/groups/{group_id}")
def delete_group(
    group_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.delete_group_from_azure(session, group_id)
    if not success:
        raise _bad_request("Error al eliminar grupo")
    return ApiResponse.ok(message="Grupo eliminado exitosamente")


@router.get("/groups")
def list_groups(
    page: int = 1,
    pageSize: int = Query(default=50, alias="pageSize"),
    filter: str | None = None,
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    result = azure_mgmt.list_groups_from_azure(page, pageSize, filter)
    return ApiResponse.ok(
        {
            "items": [dump(g) for g in result.items],
            "page": result.page,
            "pageSize": result.page_size,
            "totalCount": result.total_count,
        }
    )


@router.post("/groups/{group_id}/members/bulk-add")
def bulk_add_users_to_group(
    group_id: str,
    user_ids: list[str],
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        result = azure_mgmt.bulk_add_users_to_group(session, group_id, user_ids)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(dump(result), "Operación masiva completada")


@router.post("/groups/{group_id}/members/{user_id}")
def add_user_to_group(
    group_id: str,
    user_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.add_user_to_azure_group(session, group_id, user_id)
    if not success:
        raise _bad_request("Error al agregar usuario al grupo")
    return ApiResponse.ok(message="Usuario agregado al grupo exitosamente")


@router.delete("/groups/{group_id}/members/{user_id}")
def remove_user_from_group(
    group_id: str,
    user_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    success = azure_mgmt.remove_user_from_azure_group(session, group_id, user_id)
    if not success:
        raise _bad_request("Error al remover usuario del grupo")
    return ApiResponse.ok(message="Usuario removido del grupo exitosamente")


@router.get("/groups/{group_id}/members")
def get_group_members(
    group_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    members = azure_mgmt.get_group_members(group_id)
    return ApiResponse.ok([dump(m) for m in members])


@router.get("/users/{azure_object_id}/azure-groups")
def get_user_azure_groups(
    azure_object_id: str, _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES))
) -> ApiResponse:
    groups = azure_mgmt.get_user_azure_groups(azure_object_id)
    return ApiResponse.ok([dump(g) for g in groups])


# ========== OPERACIONES MASIVAS ==========


@router.post("/users/bulk-create")
def bulk_create_users(
    users: list[CreateAzureUserRequest],
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        result = azure_mgmt.bulk_create_users(session, users)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(dump(result), "Operación masiva completada")


# ========== SINCRONIZACIÓN ==========


@router.post("/sync/user/{azure_object_id}")
def sync_user_to_local_db(
    azure_object_id: str,
    session: Session = Depends(get_db_session),
    _actor_id: UUID = Depends(require_roles(*_ADMIN_ROLES)),
) -> ApiResponse:
    try:
        result = azure_mgmt.sync_user_to_local_db(session, azure_object_id)
    except Exception as exc:
        raise _bad_request(str(exc)) from exc
    return ApiResponse.ok(dump(result), "Sincronización completada")
