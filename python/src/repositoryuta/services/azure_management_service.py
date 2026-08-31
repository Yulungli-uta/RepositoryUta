import logging
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

import requests
from sqlalchemy.orm import Session

from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.repositories.azure_ad_repository import AzureAdRepository
from repositoryuta.schemas.audit import AuditLogCreate
from repositoryuta.schemas.azure_management import (
    AzureGroupRead,
    AzureRoleRead,
    AzureUserRead,
    BulkOperationErrorRead,
    BulkOperationResultRead,
    CreateAzureGroupRequest,
    CreateAzureUserRequest,
    PasswordValidationResultRead,
    SyncResultRead,
    UpdateAzureGroupRequest,
    UpdateAzureUserRequest,
)
from repositoryuta.services import graph_client
from repositoryuta.services.graph_client import encode_path_segment, graph_request

logger = logging.getLogger(__name__)

# Espejo de AzureManagementService.cs. Ver graph_client.py para la decision
# de arquitectura (msal + requests, no msgraph-sdk).

_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def reset_token_cache() -> None:
    """Solo para pruebas."""
    graph_client.reset_token_cache()


class EntraSyncStatus(StrEnum):
    """Espejo del enum EntraSyncStatus."""

    UNKNOWN = "Unknown"
    PENDING_SYNC = "PendingSync"
    SYNCED = "Synced"
    DISABLED = "Disabled"
    SYNC_ERROR = "SyncError"


@dataclass
class EntraSyncResult:
    """Espejo del record EntraSyncResult."""

    status: EntraSyncStatus
    account_enabled: bool | None = None
    azure_object_id: str | None = None
    message: str | None = None


@dataclass
class PagedAzureResult[T]:
    items: list[T]
    page: int
    page_size: int
    total_count: int


def _normalize_paging(page: int, page_size: int) -> tuple[int, int]:
    page = max(page, 1)
    page_size = _DEFAULT_PAGE_SIZE if page_size < 1 else min(page_size, _MAX_PAGE_SIZE)
    return page, page_size


def _is_valid_email(email: str) -> bool:
    return bool(email) and bool(_EMAIL_RE.match(email))


def _map_user(user: dict) -> AzureUserRead:
    return AzureUserRead(
        id=user["id"],
        email=user.get("userPrincipalName") or user.get("mail") or "",
        display_name=user.get("displayName") or "",
        given_name=user.get("givenName"),
        surname=user.get("surname"),
        job_title=user.get("jobTitle"),
        department=user.get("department"),
        office_location=user.get("officeLocation"),
        mobile_phone=user.get("mobilePhone"),
        business_phones=user.get("businessPhones"),
        street_address=user.get("streetAddress"),
        city=user.get("city"),
        state=user.get("state"),
        country=user.get("country"),
        postal_code=user.get("postalCode"),
        usage_location=user.get("usageLocation"),
        employee_id=user.get("employeeId"),
        company_name=user.get("companyName"),
        account_enabled=user.get("accountEnabled") or False,
        created_date_time=user.get("createdDateTime"),
        last_password_change_date_time=user.get("lastPasswordChangeDateTime"),
        user_type=user.get("userType"),
        assigned_licenses=[
            lic["skuId"] for lic in (user.get("assignedLicenses") or []) if lic.get("skuId")
        ]
        or None,
    )


def _group_type(group: dict) -> str:
    return "Microsoft365" if "Unified" in (group.get("groupTypes") or []) else "Security"


def _map_group(group: dict, *, member_count: int = 0) -> AzureGroupRead:
    return AzureGroupRead(
        id=group["id"],
        display_name=group.get("displayName") or "",
        description=group.get("description"),
        mail=group.get("mail"),
        mail_nickname=group.get("mailNickname"),
        mail_enabled=group.get("mailEnabled") or False,
        security_enabled=group.get("securityEnabled") or False,
        group_type=_group_type(group),
        created_date_time=group.get("createdDateTime"),
        member_count=member_count,
        group_types=group.get("groupTypes"),
    )


# ========== USUARIOS ==========


def create_user_in_azure(session: Session, dto: CreateAzureUserRequest) -> AzureUserRead:
    logger.info("Creando usuario en Azure AD: %s", dto.email)

    if not _is_valid_email(dto.email):
        raise ValueError("Email inválido")

    validation = validate_password_policy(dto.password)
    if not validation.is_valid:
        raise ValueError(f"Contraseña no cumple con la política: {', '.join(validation.errors)}")

    body: dict[str, Any] = {
        "userPrincipalName": dto.email,
        "displayName": dto.display_name,
        "givenName": dto.given_name,
        "surname": dto.surname,
        "mailNickname": dto.mail_nickname or dto.email.split("@")[0],
        "jobTitle": dto.job_title,
        "department": dto.department,
        "officeLocation": dto.office_location,
        "mobilePhone": dto.mobile_phone,
        "streetAddress": dto.street_address,
        "city": dto.city,
        "state": dto.state,
        "country": dto.country,
        "postalCode": dto.postal_code,
        "usageLocation": dto.usage_location,
        "employeeId": dto.employee_id,
        "companyName": dto.company_name,
        "accountEnabled": dto.account_enabled,
        "passwordProfile": {
            "password": dto.password,
            "forceChangePasswordNextSignIn": dto.force_change_password_next_sign_in,
        },
    }
    if dto.business_phones and dto.business_phones.strip():
        body["businessPhones"] = [p.strip() for p in dto.business_phones.split(",")]

    response = graph_request("POST", "/users", json=body)
    response.raise_for_status()
    created = response.json()

    azure_repo = AzureAdRepository(session)
    azure_repo.create_or_update_from_azure(
        created["id"], created["userPrincipalName"], created["displayName"]
    )
    azure_repo.log_azure_sync(
        sync_type="UserCreated",
        processed=1,
        created=1,
        updated=0,
        errors=0,
        details=f"Usuario creado: {dto.email}",
    )
    AuditRepository(session).log_action(
        AuditLogCreate(
            action="CreateAzureUser",
            module="AzureManagement",
            entity_id=created["id"],
            new_values=f'{{"email": "{dto.email}", "displayName": "{dto.display_name}"}}',
        )
    )

    logger.info("Usuario creado exitosamente en Azure AD: %s", dto.email)
    return _map_user(created)


def get_user_from_azure(azure_object_id: str) -> AzureUserRead | None:
    select = (
        "id,userPrincipalName,displayName,givenName,surname,jobTitle,department,"
        "officeLocation,mobilePhone,businessPhones,streetAddress,city,state,country,"
        "postalCode,usageLocation,employeeId,companyName,accountEnabled,createdDateTime,"
        "lastPasswordChangeDateTime,userType,assignedLicenses"
    )
    response = graph_request(
        "GET", f"/users/{encode_path_segment(azure_object_id)}", params={"$select": select}
    )
    if response.status_code == 404:
        return None
    if not response.ok:
        logger.error("Error al obtener usuario de Azure AD. AzureObjectId=%s", azure_object_id)
        return None
    return _map_user(response.json())


def get_user_by_email_from_azure(email: str) -> AzureUserRead | None:
    safe = email.replace("'", "''").strip()
    select = (
        "id,userPrincipalName,mail,displayName,givenName,surname,jobTitle,department,"
        "officeLocation,mobilePhone,businessPhones,accountEnabled,createdDateTime,userType"
    )
    response = graph_request(
        "GET",
        "/users",
        params={
            "$filter": f"(userPrincipalName eq '{safe}' or mail eq '{safe}')",
            "$select": select,
        },
    )
    if not response.ok:
        logger.error("Error al buscar usuario por correo. Email=%s", email)
        return None
    users = response.json().get("value", [])
    return _map_user(users[0]) if users else None


def update_user_in_azure(
    session: Session, azure_object_id: str, dto: UpdateAzureUserRequest
) -> AzureUserRead | None:
    logger.info("Actualizando usuario en Azure AD: %s", azure_object_id)
    body: dict[str, Any] = {
        "displayName": dto.display_name,
        "givenName": dto.given_name,
        "surname": dto.surname,
        "jobTitle": dto.job_title,
        "department": dto.department,
        "officeLocation": dto.office_location,
        "mobilePhone": dto.mobile_phone,
        "streetAddress": dto.street_address,
        "city": dto.city,
        "state": dto.state,
        "country": dto.country,
        "postalCode": dto.postal_code,
        "usageLocation": dto.usage_location,
        "employeeId": dto.employee_id,
        "companyName": dto.company_name,
        "accountEnabled": dto.account_enabled,
    }
    if dto.business_phones and dto.business_phones.strip():
        body["businessPhones"] = [p.strip() for p in dto.business_phones.split(",")]

    response = graph_request(
        "PATCH", f"/users/{encode_path_segment(azure_object_id)}", json=body
    )
    response.raise_for_status()

    updated_user = get_user_from_azure(azure_object_id)
    if updated_user is not None:
        azure_repo = AzureAdRepository(session)
        azure_repo.create_or_update_from_azure(
            azure_object_id, updated_user.email, updated_user.display_name
        )
        azure_repo.log_azure_sync(
            sync_type="UserUpdated",
            processed=1,
            created=0,
            updated=1,
            errors=0,
            details=f"Usuario actualizado: {updated_user.email}",
        )
        AuditRepository(session).log_action(
            AuditLogCreate(
                action="UpdateAzureUser",
                module="AzureManagement",
                entity_id=azure_object_id,
                new_values=dto.model_dump_json(),
            )
        )

    logger.info("Usuario actualizado exitosamente en Azure AD: %s", azure_object_id)
    return updated_user


def enable_disable_user_in_azure(session: Session, azure_object_id: str, enable: bool) -> bool:
    response = graph_request(
        "PATCH",
        f"/users/{encode_path_segment(azure_object_id)}",
        json={"accountEnabled": enable},
    )
    if not response.ok:
        logger.error("Error al habilitar/deshabilitar usuario. AzureObjectId=%s", azure_object_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="EnableAzureUser" if enable else "DisableAzureUser",
            module="AzureManagement",
            entity_id=azure_object_id,
            new_values=f"AccountEnabled: {enable}",
        )
    )
    return True


def delete_user_from_azure(
    session: Session, azure_object_id: str, permanent_delete: bool = False
) -> bool:
    response = graph_request("DELETE", f"/users/{encode_path_segment(azure_object_id)}")
    if not response.ok:
        logger.error("Error al eliminar usuario de Azure AD. AzureObjectId=%s", azure_object_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="DeleteAzureUser",
            module="AzureManagement",
            entity_id=azure_object_id,
            new_values=f"PermanentDelete: {permanent_delete}",
        )
    )
    return True


def list_users_from_azure(
    page: int = 1, page_size: int = _DEFAULT_PAGE_SIZE, user_filter: str | None = None
) -> PagedAzureResult[AzureUserRead]:
    page, page_size = _normalize_paging(page, page_size)
    select = (
        "id,userPrincipalName,displayName,givenName,surname,jobTitle,department,"
        "accountEnabled,createdDateTime,userType"
    )
    params: dict[str, Any] = {
        "$top": page_size,
        "$count": "true",
        "$select": select,
        "$orderby": "displayName",
    }
    if user_filter:
        params["$filter"] = user_filter
    headers = {"ConsistencyLevel": "eventual"}

    response = graph_request("GET", "/users", params=params, headers=headers)
    if not response.ok:
        logger.error("Error al listar usuarios de Azure AD")
        return PagedAzureResult(items=[], page=page, page_size=page_size, total_count=0)

    first = response.json()
    total_count = first.get("@odata.count")

    current = first
    hops = 1
    while hops < page and current.get("@odata.nextLink"):
        next_response = graph_request("GET", current["@odata.nextLink"], headers=headers)
        next_response.raise_for_status()
        current = next_response.json()
        hops += 1

    items = [_map_user(u) for u in current.get("value", [])]
    total = total_count if total_count is not None else len(items)
    return PagedAzureResult(items=items, page=page, page_size=page_size, total_count=total)


# ========== CONTRASEÑAS ==========


def validate_password_policy(password: str) -> PasswordValidationResultRead:
    errors: list[str] = []
    score = 0

    if not password or not password.strip():
        return PasswordValidationResultRead(
            is_valid=False, errors=["La contraseña no puede estar vacía"], strength_score=0,
            strength_level="Muy débil",
        )

    if len(password) < 8:
        errors.append("La contraseña debe tener al menos 8 caracteres")
    else:
        score += 20
    if not re.search(r"[A-Z]", password):
        errors.append("Debe contener al menos una mayúscula")
    else:
        score += 20
    if not re.search(r"[a-z]", password):
        errors.append("Debe contener al menos una minúscula")
    else:
        score += 20
    if not re.search(r"[0-9]", password):
        errors.append("Debe contener al menos un número")
    else:
        score += 20
    if not re.search(r"""[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]""", password):
        errors.append("Debe contener al menos un carácter especial")
    else:
        score += 20

    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10

    if score >= 80:
        strength_level = "Muy fuerte"
    elif score >= 60:
        strength_level = "Fuerte"
    elif score >= 40:
        strength_level = "Media"
    elif score >= 20:
        strength_level = "Débil"
    else:
        strength_level = "Muy débil"

    return PasswordValidationResultRead(
        is_valid=len(errors) == 0,
        errors=errors,
        strength_score=score,
        strength_level=strength_level,
    )


def generate_secure_password() -> str:
    """Espejo de GenerateSecurePasswordAsync: 1 char de cada categoria
    obligatoria + relleno aleatorio hasta 16, luego mezclado."""
    uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowercase = "abcdefghijklmnopqrstuvwxyz"
    digits = "0123456789"
    special = "!@#$%^&*()_+-=[]{}"
    all_chars = uppercase + lowercase + digits + special

    chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    chars.extend(secrets.choice(all_chars) for _ in range(4, 16))

    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def reset_password_in_azure(
    session: Session, azure_object_id: str, force_change: bool = True
) -> str:
    temp_password = generate_secure_password()
    body = {
        "passwordProfile": {
            "password": temp_password,
            "forceChangePasswordNextSignIn": force_change,
        }
    }
    response = graph_request(
        "PATCH", f"/users/{encode_path_segment(azure_object_id)}", json=body
    )
    response.raise_for_status()

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="ResetPasswordAzureUser",
            module="AzureManagement",
            entity_id=azure_object_id,
            new_values=f"ForceChange: {force_change}",
        )
    )
    logger.info("Contraseña reseteada para usuario: %s", azure_object_id)
    return temp_password


def change_password_in_azure(
    session: Session,
    azure_object_id: str,
    new_password: str,
    force_change_next_sign_in: bool = False,
) -> bool:
    validation = validate_password_policy(new_password)
    if not validation.is_valid:
        raise ValueError(f"Contraseña no cumple con la política: {', '.join(validation.errors)}")

    body = {
        "passwordProfile": {
            "password": new_password,
            "forceChangePasswordNextSignIn": force_change_next_sign_in,
        }
    }
    response = graph_request(
        "PATCH", f"/users/{encode_path_segment(azure_object_id)}", json=body
    )
    if not response.ok:
        logger.error("Error al cambiar contraseña. AzureObjectId=%s", azure_object_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="ChangePasswordAzureUser", module="AzureManagement", entity_id=azure_object_id
        )
    )
    logger.info("Contraseña cambiada para usuario: %s", azure_object_id)
    return True


# ========== ROLES ==========


def get_all_azure_directory_roles() -> list[AzureRoleRead]:
    response = graph_request("GET", "/directoryRoles")
    if not response.ok:
        logger.error("Error al obtener roles de directorio")
        return []
    return [
        AzureRoleRead(
            id=r["id"],
            display_name=r.get("displayName") or "",
            description=r.get("description"),
            is_built_in=True,
            role_template_id=r.get("roleTemplateId"),
        )
        for r in response.json().get("value", [])
    ]


def get_user_azure_roles(azure_object_id: str) -> list[AzureRoleRead]:
    results: list[AzureRoleRead] = []
    response = graph_request(
        "GET",
        f"/users/{encode_path_segment(azure_object_id)}/memberOf",
        params={"$select": "id,displayName,description"},
    )
    if not response.ok:
        logger.error("Error al obtener miembros del usuario")
        return []

    page = response.json()
    while True:
        for obj in page.get("value", []):
            odata_type = obj.get("@odata.type", "")
            if odata_type.endswith("group"):
                results.append(
                    AzureRoleRead(
                        id=obj["id"],
                        display_name=obj.get("displayName") or "(Sin nombre)",
                        description=obj.get("description"),
                        is_built_in=False,
                        role_template_id=None,
                    )
                )
            elif odata_type.endswith("directoryRole"):
                results.append(
                    AzureRoleRead(
                        id=obj["id"],
                        display_name=obj.get("displayName") or "(Sin nombre)",
                        description=obj.get("description"),
                        is_built_in=True,
                        role_template_id=obj.get("roleTemplateId"),
                    )
                )

        next_link = page.get("@odata.nextLink")
        if not next_link:
            break
        next_response = graph_request("GET", next_link)
        if not next_response.ok:
            break
        page = next_response.json()

    return results


def assign_azure_role(session: Session, azure_object_id: str, role_id: str) -> bool:
    body = {
        "@odata.id": (
            f"{graph_client.GRAPH_BASE_URL}/directoryObjects/"
            f"{encode_path_segment(azure_object_id)}"
        )
    }
    response = graph_request(
        "POST", f"/directoryRoles/{encode_path_segment(role_id)}/members/$ref", json=body
    )
    if not response.ok:
        logger.error("Error al asignar rol. RoleId=%s, AzureObjectId=%s", role_id, azure_object_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AssignAzureRole",
            module="AzureManagement",
            entity_id=azure_object_id,
            new_values=f"RoleId: {role_id}",
        )
    )
    return True


def remove_azure_role(session: Session, azure_object_id: str, role_id: str) -> bool:
    response = graph_request(
        "DELETE",
        f"/directoryRoles/{encode_path_segment(role_id)}"
        f"/members/{encode_path_segment(azure_object_id)}/$ref",
    )
    if not response.ok:
        logger.error("Error al remover rol. RoleId=%s, AzureObjectId=%s", role_id, azure_object_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="RemoveAzureRole",
            module="AzureManagement",
            entity_id=azure_object_id,
            old_values=f"RoleId: {role_id}",
        )
    )
    return True


def get_role_members(role_id: str) -> list[AzureUserRead]:
    response = graph_request("GET", f"/directoryRoles/{encode_path_segment(role_id)}/members")
    if not response.ok:
        logger.error("Error al obtener miembros del rol. RoleId=%s", role_id)
        return []
    return [
        _map_user(u)
        for u in response.json().get("value", [])
        if u.get("@odata.type", "").endswith("user")
    ]


# ========== GRUPOS ==========


def create_group_in_azure(session: Session, dto: CreateAzureGroupRequest) -> AzureGroupRead:
    body = {
        "displayName": dto.display_name,
        "description": dto.description,
        "mailNickname": dto.mail_nickname or dto.display_name.replace(" ", "").lower(),
        "mailEnabled": dto.mail_enabled,
        "securityEnabled": dto.security_enabled,
        "groupTypes": ["Unified"] if dto.group_type == "Microsoft365" else [],
    }
    response = graph_request("POST", "/groups", json=body)
    response.raise_for_status()
    created = response.json()
    group_id = created["id"]

    for owner_id in dto.owners or []:
        try:
            ref_body = {
                "@odata.id": f"{graph_client.GRAPH_BASE_URL}/users/{encode_path_segment(owner_id)}"
            }
            owner_response = graph_request(
                "POST",
                f"/groups/{encode_path_segment(group_id)}/owners/$ref",
                json=ref_body,
            )
            owner_response.raise_for_status()
        except requests.RequestException:
            logger.warning("Error al agregar owner %s", owner_id)

    for member_id in dto.members or []:
        add_user_to_azure_group(session, group_id, member_id)

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="CreateAzureGroup",
            module="AzureManagement",
            entity_id=group_id,
            new_values=f'{{"displayName": "{dto.display_name}", "groupType": "{dto.group_type}"}}',
        )
    )
    return _map_group(created, member_count=0)


def get_group_from_azure(group_id: str) -> AzureGroupRead | None:
    select = (
        "id,displayName,description,mail,mailNickname,mailEnabled,securityEnabled,"
        "groupTypes,createdDateTime"
    )
    response = graph_request(
        "GET", f"/groups/{encode_path_segment(group_id)}", params={"$select": select}
    )
    if response.status_code == 404:
        return None
    if not response.ok:
        logger.error("Error al obtener grupo. GroupId=%s", group_id)
        return None
    group = response.json()

    members_response = graph_request(
        "GET", f"/groups/{encode_path_segment(group_id)}/members"
    )
    member_count = len(members_response.json().get("value", [])) if members_response.ok else 0

    return _map_group(group, member_count=member_count)


def update_group_in_azure(
    session: Session, group_id: str, dto: UpdateAzureGroupRequest
) -> AzureGroupRead | None:
    body = {
        "displayName": dto.display_name,
        "description": dto.description,
        "mailNickname": dto.mail_nickname,
    }
    response = graph_request(
        "PATCH", f"/groups/{encode_path_segment(group_id)}", json=body
    )
    if not response.ok:
        logger.error("Error al actualizar grupo. GroupId=%s", group_id)
        return None

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="UpdateAzureGroup",
            module="AzureManagement",
            entity_id=group_id,
            new_values=dto.model_dump_json(),
        )
    )
    return get_group_from_azure(group_id)


def delete_group_from_azure(session: Session, group_id: str) -> bool:
    response = graph_request("DELETE", f"/groups/{encode_path_segment(group_id)}")
    if not response.ok:
        logger.error("Error al eliminar grupo. GroupId=%s", group_id)
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(action="DeleteAzureGroup", module="AzureManagement", entity_id=group_id)
    )
    return True


def list_groups_from_azure(
    page: int = 1, page_size: int = _DEFAULT_PAGE_SIZE, group_filter: str | None = None
) -> PagedAzureResult[AzureGroupRead]:
    page, page_size = _normalize_paging(page, page_size)
    select = (
        "id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,createdDateTime"
    )
    params: dict[str, Any] = {"$top": page_size, "$select": select, "$orderby": "displayName"}
    if group_filter:
        params["$filter"] = group_filter

    response = graph_request("GET", "/groups", params=params)
    if not response.ok:
        logger.error("Error al listar grupos")
        return PagedAzureResult(items=[], page=page, page_size=page_size, total_count=0)

    payload = response.json()
    items = [_map_group(g) for g in payload.get("value", [])]
    total = payload.get("@odata.count", len(items))
    return PagedAzureResult(items=items, page=page, page_size=page_size, total_count=total)


def add_user_to_azure_group(session: Session, group_id: str, azure_object_id: str) -> bool:
    body = {
        "@odata.id": (
            f"{graph_client.GRAPH_BASE_URL}/directoryObjects/"
            f"{encode_path_segment(azure_object_id)}"
        )
    }
    response = graph_request(
        "POST", f"/groups/{encode_path_segment(group_id)}/members/$ref", json=body
    )
    if not response.ok:
        logger.error(
            "Error al agregar usuario al grupo. GroupId=%s, AzureObjectId=%s",
            group_id, azure_object_id,
        )
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="AddUserToAzureGroup",
            module="AzureManagement",
            entity_id=azure_object_id,
            new_values=f"GroupId: {group_id}",
        )
    )
    return True


def remove_user_from_azure_group(session: Session, group_id: str, azure_object_id: str) -> bool:
    response = graph_request(
        "DELETE",
        f"/groups/{encode_path_segment(group_id)}"
        f"/members/{encode_path_segment(azure_object_id)}/$ref",
    )
    if not response.ok:
        logger.error(
            "Error al remover usuario del grupo. GroupId=%s, AzureObjectId=%s",
            group_id, azure_object_id,
        )
        return False

    AuditRepository(session).log_action(
        AuditLogCreate(
            action="RemoveUserFromAzureGroup",
            module="AzureManagement",
            entity_id=azure_object_id,
            old_values=f"GroupId: {group_id}",
        )
    )
    return True


def get_group_members(group_id: str) -> list[AzureUserRead]:
    response = graph_request("GET", f"/groups/{encode_path_segment(group_id)}/members")
    if not response.ok:
        logger.error("Error al obtener miembros del grupo. GroupId=%s", group_id)
        return []
    return [
        _map_user(u)
        for u in response.json().get("value", [])
        if u.get("@odata.type", "").endswith("user")
    ]


def get_user_azure_groups(azure_object_id: str) -> list[AzureGroupRead]:
    """Espejo de GetUserAzureGroupsAsync: solo grupos cuyo nombre empieza con
    "Rol" (mismo filtro que el .NET real)."""
    logger.info("Obteniendo grupos del usuario %s desde Azure AD", azure_object_id)
    select = (
        "id,displayName,description,mail,mailNickname,mailEnabled,securityEnabled,"
        "groupTypes,createdDateTime"
    )
    response = graph_request(
        "GET",
        f"/users/{encode_path_segment(azure_object_id)}/memberOf/microsoft.graph.group",
        params={"$select": select, "$top": 999},
    )
    if not response.ok:
        logger.error("Error al obtener grupos del usuario. AzureObjectId=%s", azure_object_id)
        return []

    all_groups: list[dict] = []
    page = response.json()
    while True:
        all_groups.extend(page.get("value", []))
        next_link = page.get("@odata.nextLink")
        if not next_link:
            break
        next_response = graph_request("GET", next_link)
        if not next_response.ok:
            break
        page = next_response.json()

    filtered = [
        g for g in all_groups if (g.get("displayName") or "").lower().startswith("rol")
    ]
    return [_map_group(g) for g in filtered]


# ========== OPERACIONES MASIVAS ==========


def bulk_create_users(
    session: Session, users: list[CreateAzureUserRequest]
) -> BulkOperationResultRead:
    start = time.monotonic()
    successful = 0
    errors: list[BulkOperationErrorRead] = []

    for user_dto in users:
        try:
            create_user_in_azure(session, user_dto)
            successful += 1
        except Exception as exc:
            errors.append(
                BulkOperationErrorRead(
                    identifier=user_dto.email, error_message=str(exc), error_code="CREATE_FAILED"
                )
            )

    return BulkOperationResultRead(
        total_requested=len(users),
        successful=successful,
        failed=len(errors),
        errors=errors,
        duration_seconds=time.monotonic() - start,
    )


def bulk_add_users_to_group(
    session: Session, group_id: str, user_ids: list[str]
) -> BulkOperationResultRead:
    start = time.monotonic()
    successful = 0
    errors: list[BulkOperationErrorRead] = []

    for user_id in user_ids:
        try:
            if add_user_to_azure_group(session, group_id, user_id):
                successful += 1
            else:
                errors.append(
                    BulkOperationErrorRead(
                        identifier=user_id,
                        error_message="Failed to add user to group",
                        error_code="ADD_FAILED",
                    )
                )
        except Exception as exc:
            errors.append(
                BulkOperationErrorRead(
                    identifier=user_id, error_message=str(exc), error_code="ADD_FAILED"
                )
            )

    return BulkOperationResultRead(
        total_requested=len(user_ids),
        successful=successful,
        failed=len(errors),
        errors=errors,
        duration_seconds=time.monotonic() - start,
    )


# ========== SINCRONIZACIÓN ==========


def sync_user_to_local_db(session: Session, azure_object_id: str) -> SyncResultRead:
    start = time.monotonic()
    errors: list[str] = []

    try:
        user = get_user_from_azure(azure_object_id)
        if user is None:
            errors.append(f"Usuario no encontrado en Azure AD: {azure_object_id}")
            return SyncResultRead(
                success=False, users_processed=0, users_created=0, users_updated=0,
                users_failed=1, groups_processed=0, groups_created=0, groups_updated=0,
                errors=errors, sync_date_time=datetime.now(),
                duration_seconds=time.monotonic() - start,
            )

        azure_repo = AzureAdRepository(session)
        existing_user = azure_repo.find_by_azure_id(UUID(azure_object_id))
        is_new = existing_user is None

        azure_repo.create_or_update_from_azure(azure_object_id, user.email, user.display_name)
        azure_repo.log_azure_sync(
            sync_type="ManualSync",
            processed=1,
            created=1 if is_new else 0,
            updated=0 if is_new else 1,
            errors=0,
            details=f"Usuario sincronizado: {user.email}",
        )

        return SyncResultRead(
            success=True, users_processed=1, users_created=1 if is_new else 0,
            users_updated=0 if is_new else 1, users_failed=0, groups_processed=0,
            groups_created=0, groups_updated=0, errors=errors, sync_date_time=datetime.now(),
            duration_seconds=time.monotonic() - start,
        )
    except Exception as exc:
        errors.append(f"Error al sincronizar usuario: {exc}")
        return SyncResultRead(
            success=False, users_processed=0, users_created=0, users_updated=0,
            users_failed=1, groups_processed=0, groups_created=0, groups_updated=0,
            errors=errors, sync_date_time=datetime.now(), duration_seconds=time.monotonic() - start,
        )


# ========== VERIFICACIÓN SYNC AD LOCAL → ENTRA ==========


def check_user_entra_sync(upn: str) -> EntraSyncResult:
    """Espejo de AzureManagementService.CheckUserEntraSyncAsync: verifica si
    un usuario de AD Local ya sincronizo a Microsoft Entra (por UPN)."""
    safe = upn.replace("'", "''").strip()
    try:
        response = graph_request(
            "GET",
            "/users",
            params={
                "$filter": f"userPrincipalName eq '{safe}'",
                "$select": "id,userPrincipalName,accountEnabled",
            },
        )
        response.raise_for_status()
        users = response.json().get("value", [])
        user = users[0] if users else None

        if user is None:
            return EntraSyncResult(
                status=EntraSyncStatus.PENDING_SYNC,
                message=(
                    "Usuario no encontrado en Microsoft Entra. "
                    "Pendiente de sincronización con Entra Connect."
                ),
            )

        enabled = user.get("accountEnabled")
        status = EntraSyncStatus.SYNCED if enabled else EntraSyncStatus.DISABLED
        message = (
            "Sincronizado y habilitado en Microsoft Entra."
            if enabled
            else "Sincronizado en Microsoft Entra, pero la cuenta está deshabilitada."
        )
        return EntraSyncResult(
            status=status, account_enabled=enabled, azure_object_id=user.get("id"), message=message
        )
    except requests.HTTPError as exc:
        logger.error("Error Graph al verificar sync Entra para UPN=%s: %s", upn, exc)
        return EntraSyncResult(
            status=EntraSyncStatus.SYNC_ERROR,
            message=f"Error al consultar Microsoft Entra: {exc}",
        )
    except Exception:
        logger.exception("Error inesperado al verificar sync Entra para UPN=%s", upn)
        return EntraSyncResult(
            status=EntraSyncStatus.SYNC_ERROR,
            message="Error inesperado al verificar sincronización.",
        )
