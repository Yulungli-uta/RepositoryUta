from datetime import datetime

from repositoryuta.core.schema_base import ApiModel


class CreateAzureUserRequest(ApiModel):
    email: str
    display_name: str
    given_name: str
    surname: str
    password: str
    force_change_password_next_sign_in: bool = True
    mail_nickname: str | None = None
    job_title: str | None = None
    department: str | None = None
    office_location: str | None = None
    mobile_phone: str | None = None
    business_phones: str | None = None
    street_address: str | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None
    postal_code: str | None = None
    usage_location: str | None = None
    employee_id: str | None = None
    company_name: str | None = None
    account_enabled: bool = True


class UpdateAzureUserRequest(ApiModel):
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    job_title: str | None = None
    department: str | None = None
    office_location: str | None = None
    mobile_phone: str | None = None
    business_phones: str | None = None
    street_address: str | None = None
    city: str | None = None
    state: str | None = None
    country: str | None = None
    postal_code: str | None = None
    usage_location: str | None = None
    employee_id: str | None = None
    company_name: str | None = None
    account_enabled: bool | None = None


class AzureUserRead(ApiModel):
    id: str
    email: str
    display_name: str
    given_name: str | None
    surname: str | None
    job_title: str | None
    department: str | None
    office_location: str | None
    mobile_phone: str | None
    business_phones: list[str] | None
    street_address: str | None
    city: str | None
    state: str | None
    country: str | None
    postal_code: str | None
    usage_location: str | None
    employee_id: str | None
    company_name: str | None
    account_enabled: bool
    created_date_time: datetime | None
    last_password_change_date_time: datetime | None
    user_type: str | None
    assigned_licenses: list[str] | None


class PasswordValidationResultRead(ApiModel):
    is_valid: bool
    errors: list[str]
    strength_score: int
    strength_level: str


class AzureRoleRead(ApiModel):
    id: str
    display_name: str
    description: str | None
    is_built_in: bool
    role_template_id: str | None
    role_permissions: list[str] | None = None


class CreateAzureGroupRequest(ApiModel):
    display_name: str
    description: str | None = None
    mail_nickname: str | None = None
    group_type: str = "Security"
    mail_enabled: bool = False
    security_enabled: bool = True
    owners: list[str] | None = None
    members: list[str] | None = None


class UpdateAzureGroupRequest(ApiModel):
    display_name: str | None = None
    description: str | None = None
    mail_nickname: str | None = None


class AzureGroupRead(ApiModel):
    id: str
    display_name: str
    description: str | None
    mail: str | None
    mail_nickname: str | None
    mail_enabled: bool
    security_enabled: bool
    group_type: str
    created_date_time: datetime | None
    member_count: int
    group_types: list[str] | None


class BulkOperationErrorRead(ApiModel):
    identifier: str
    error_message: str
    error_code: str


class BulkOperationResultRead(ApiModel):
    total_requested: int
    successful: int
    failed: int
    errors: list[BulkOperationErrorRead]
    duration_seconds: float


class SyncResultRead(ApiModel):
    success: bool
    users_processed: int
    users_created: int
    users_updated: int
    users_failed: int
    groups_processed: int
    groups_created: int
    groups_updated: int
    errors: list[str]
    sync_date_time: datetime
    duration_seconds: float
