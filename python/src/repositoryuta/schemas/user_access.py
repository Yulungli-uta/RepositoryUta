from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class UserAccessSummary(ApiModel):
    user_id: UUID
    email: str
    display_name: str | None = None
    user_type: str
    is_active: bool
    hr_employee_id: int | None = None
    roles: list[str]
    last_microsoft_login: datetime | None = None
    last_app_access: datetime | None = None
    valid_sessions: int
    account_locked: bool = False
    locked_until: datetime | None = None


class UserAccessEvent(ApiModel):
    timestamp: datetime
    type: str
    title: str
    detail: str | None = None
    ip_address: str | None = None
    device: str | None = None
    session_id: UUID | None = None


class UserAccessTimeline(ApiModel):
    summary: UserAccessSummary
    items: list[UserAccessEvent]
    page: int
    page_size: int
    total_count: int
    total_pages: int
