from datetime import datetime

from repositoryuta.core.schema_base import ApiModel

# Espejo de ProvisioningDtos.cs / StudentProvisioningDtos.cs.


class ProvisionEmployeeRequest(ApiModel):
    hr_employee_id: int
    display_name: str
    given_name: str
    surname: str
    initial_password: str
    employee_type_id: int
    employee_type_name: str | None = None
    department_id: int | None = None
    department_name: str | None = None
    job_title: str | None = None
    source_reference: str | None = None
    force_password_change: bool = True
    personal_email: str | None = None
    # Ignorado a proposito: el email institucional siempre se genera internamente
    # (ver institutional_email_service) — igual que el .NET original.
    email: str | None = None
    id_card: str | None = None


class UserProvisioningRead(ApiModel):
    id: str
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
    auth_user_id: str | None
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


class BulkProvisioningResultRead(ApiModel):
    hr_employee_id: int
    email: str
    success: bool
    provisioning: UserProvisioningRead | None
    error: str | None


class CompletePendingResultRead(ApiModel):
    total_processed: int
    license_assigned: int
    still_pending: int
    failed: int
    results: list[UserProvisioningRead]


class RetryProvisioningRequest(ApiModel):
    initial_password: str | None = None


class DisableEmployeeResultRead(ApiModel):
    success: bool
    hr_employee_id: int
    email: str | None
    error_message: str | None


class PasswordResetResultRead(ApiModel):
    provisioning_id: str
    hr_employee_id: int
    email: str
    new_temporary_password: str
    message: str


# ─── Estudiantes ────────────────────────────────────────────────────────────


class CreateStudentAdAccountRequest(ApiModel):
    hr_student_id: int
    display_name: str
    given_name: str
    surname: str
    initial_password: str
    id_card: str | None = None
    source_reference: str | None = None
    force_password_change: bool = True


class CreateStudentAdAccountResultRead(ApiModel):
    success: bool
    ad_object_id: str | None
    email: str | None
    error_message: str | None


class DisableStudentAdAccountResultRead(ApiModel):
    success: bool
    ad_object_id: str
    error_message: str | None
