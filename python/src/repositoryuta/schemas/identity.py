from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel
from repositoryuta.models.identity import ProvisioningStatus


class UserCreate(ApiModel):
    # HrEmployeeId es obligatorio: este endpoint crea el User y su UserEmployee en
    # un solo paso (ver CreateUserDto en Models/DTOs/_Dtos.cs, bug corregido 2026-08-04
    # cuando faltaba y las cuentas quedaban sin vinculo a HR).
    email: str
    display_name: str | None = None
    hr_employee_id: int
    user_type: str = "Local"


class UserUpdate(ApiModel):
    display_name: str | None = None
    is_active: bool | None = None
    azure_object_id: UUID | None = None
    user_type: str | None = None


class UserRead(ApiModel):
    id: UUID
    email: str
    display_name: str | None
    azure_object_id: UUID | None
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    user_type: str


class UserEmployeeCreate(ApiModel):
    # HrEmployeeId obligatorio por el mismo motivo que en UserCreate: sin el, las
    # sesiones emitidas para este usuario no llevan el claim employeeId.
    user_id: UUID
    employee_email: str
    hr_employee_id: int
    is_active: bool | None = None
    sync_date: datetime | None = None
    notes: str | None = None


class UserEmployeeUpdate(ApiModel):
    is_active: bool | None = None
    sync_date: datetime | None = None
    notes: str | None = None


class UserEmployeeRead(ApiModel):
    id: int
    user_id: UUID
    employee_email: str
    hr_employee_id: int | None
    is_active: bool
    sync_date: datetime | None
    notes: str | None


class LocalCredentialCreate(ApiModel):
    user_id: UUID
    password_hash: str
    must_change_password: bool | None = None


class LocalCredentialUpdate(ApiModel):
    password_hash: str | None = None
    must_change_password: bool | None = None
    failed_attempts: int | None = None
    is_locked: bool | None = None
    password_expires_at: datetime | None = None


class SecurityTokenCreate(ApiModel):
    user_id: UUID
    token_type: str
    token_hash: str
    expires_at: datetime
    additional_data: str | None = None


class SecurityTokenUpdate(ApiModel):
    is_used: bool | None = None
    expires_at: datetime | None = None
    additional_data: str | None = None


class SecurityTokenRead(ApiModel):
    id: UUID
    user_id: UUID
    token_type: str
    token_hash: str
    expires_at: datetime
    is_used: bool
    created_at: datetime
    additional_data: str | None


class LocalCredentialRead(ApiModel):
    """Espejo EXACTO de lo que LocalCredentialsController.cs devuelve: la
    entidad completa, incluido `password_hash`/`two_factor_secret` (nunca en
    claro, pero sí el hash/secreto TOTP) — el .NET real no usa un DTO de
    lectura acotado aquí, solo `ApiResponse.Ok(entity)`. No se recorta sin
    aprobación explícita aunque exponer un hash sea discutible; endpoint ya
    restringido a Administrador/R_DITIC."""

    user_id: UUID
    password_hash: str
    password_created_at: datetime
    password_expires_at: datetime | None
    must_change_password: bool
    failed_attempts: int
    last_failed_attempt: datetime | None
    locked_until: datetime | None
    is_locked: bool
    two_factor_enabled: bool
    two_factor_secret: str | None
    security_questions: str | None


class PasswordHistoryCreate(ApiModel):
    # Sin Update: PasswordHistory es de solo insercion (UpdatePasswordHistoryDto
    # en .NET es un no-op explicito).
    user_id: UUID
    password_hash: str


class UserAccountLockCreate(ApiModel):
    user_id: UUID
    lock_type: str
    lock_reason: str
    auto_unlock_at: datetime | None = None
    locked_by: str | None = None


class UserAccountLockUpdate(ApiModel):
    is_active: bool | None = None
    unlocked_at: datetime | None = None
    unlocked_by: str | None = None


class UserActivityLogCreate(ApiModel):
    user_id: UUID
    session_id: UUID | None = None
    activity: str
    activity_details: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    module_accessed: str | None = None
    action_performed: str | None = None


class UserActivityLogUpdate(ApiModel):
    activity_details: str | None = None


class UserActivityLogRead(ApiModel):
    id: int
    user_id: UUID
    session_id: UUID | None
    activity: str
    activity_details: str | None
    ip_address: str | None
    user_agent: str | None
    timestamp: datetime
    module_accessed: str | None
    action_performed: str | None


class ChangePasswordRequest(ApiModel):
    current_password: str
    new_password: str


class ChangePasswordResponse(ApiModel):
    success: bool
    message: str


class ChangePasswordWith2FARequest(ApiModel):
    """CurrentPassword requerida para usuarios locales; se omite para AzureAD
    (fuera de alcance de este corte, ver AuthService.cs)."""

    current_password: str | None = None
    new_password: str
    otp_code: str


class RequestPasswordChange2FAResponse(ApiModel):
    success: bool
    message: str
    otp_code_dev: str | None = None
    """Solo presente en entorno de desarrollo para pruebas."""


class UserProvisioningRead(ApiModel):
    """Espejo de UserProvisioningDto (Models/DTOs/ProvisioningDtos.cs).

    Los DTOs de flujo (ProvisionEmployeeRequest, RetryProvisioningRequest, ...)
    quedan fuera de este corte: pertenecen a EmployeeProvisioningService (Fase 4),
    no a la persistencia pura de este registro.
    """

    id: UUID
    hr_employee_id: int
    email: str
    display_name: str
    given_name: str | None
    surname: str | None
    department_id: int | None
    department_name: str | None
    job_title: str | None
    employee_type_id: int
    employee_type_name: str | None
    provisioning_status_id: int
    provisioning_status_name: str | None
    auth_user_id: UUID | None
    local_ad_object_id: str | None
    entra_object_id: str | None
    license_sku_id: str | None
    provisioned_at: datetime | None
    license_assigned_at: datetime | None
    last_checked_at: datetime | None
    error_message: str | None
    requested_by: str | None
    source_reference: str | None
    created_at: datetime
    updated_at: datetime | None
    warning: str | None = None


__all__ = [
    "ChangePasswordRequest",
    "ChangePasswordResponse",
    "ChangePasswordWith2FARequest",
    "LocalCredentialCreate",
    "LocalCredentialRead",
    "LocalCredentialUpdate",
    "PasswordHistoryCreate",
    "ProvisioningStatus",
    "RequestPasswordChange2FAResponse",
    "SecurityTokenCreate",
    "SecurityTokenRead",
    "SecurityTokenUpdate",
    "UserAccountLockCreate",
    "UserAccountLockUpdate",
    "UserActivityLogCreate",
    "UserActivityLogRead",
    "UserActivityLogUpdate",
    "UserCreate",
    "UserEmployeeCreate",
    "UserEmployeeRead",
    "UserEmployeeUpdate",
    "UserProvisioningRead",
    "UserRead",
    "UserUpdate",
]
