from repositoryuta.core.schema_base import ApiModel


class LocalAdAuthRequest(ApiModel):
    username: str
    password: str


class LocalAdAuthResponse(ApiModel):
    success: bool
    email: str | None = None
    display_name: str | None = None
    failure_reason: str | None = None


class CreateLocalAdUserRequest(ApiModel):
    email: str
    display_name: str
    given_name: str | None = None
    surname: str | None = None
    initial_password: str
    force_password_change: bool = True
    job_title: str | None = None
    department: str | None = None
    account_enabled: bool = True
    target_ou: str | None = None


class UpdateLocalAdUserRequest(ApiModel):
    display_name: str | None = None
    given_name: str | None = None
    surname: str | None = None
    job_title: str | None = None
    department: str | None = None


class LocalAdUserResponse(ApiModel):
    id: str
    email: str
    display_name: str
    given_name: str | None
    surname: str | None
    job_title: str | None
    department: str | None
    account_enabled: bool


class LocalAdGroupResponse(ApiModel):
    id: str
    name: str
    description: str | None
    email: str | None


class CreateLocalAdGroupRequest(ApiModel):
    group_name: str
    description: str | None = None


class ChangeLocalAdUserPasswordRequest(ApiModel):
    new_password: str
    force_password_change: bool = True


class EntraSyncResultRead(ApiModel):
    status: str
    account_enabled: bool | None = None
    azure_object_id: str | None = None
    message: str | None = None


class LocalAdUserWithSyncResponse(ApiModel):
    id: str
    email: str
    display_name: str
    given_name: str | None
    surname: str | None
    job_title: str | None
    department: str | None
    account_enabled: bool
    entra_sync: EntraSyncResultRead | None = None
