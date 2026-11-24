from datetime import datetime
from uuid import UUID

from repositoryuta.core.schema_base import ApiModel


class NotificationSubscriptionCreate(ApiModel):
    application_id: UUID
    event_type: str
    webhook_url: str
    secret_key: str | None = None


class NotificationSubscriptionUpdate(ApiModel):
    webhook_url: str | None = None
    secret_key: str | None = None
    is_active: bool | None = None


class NotificationLogCreate(ApiModel):
    subscription_id: UUID
    event_type: str
    user_id: UUID | None = None
    webhook_url: str | None = None
    http_status_code: int | None = None
    response_body: str | None = None
    response_time: int | None = None
    is_success: bool = False
    error_message: str | None = None


class NotificationSubscriptionRead(ApiModel):
    id: UUID
    application_id: UUID
    event_type: str
    webhook_url: str | None
    notification_type: str
    is_active: bool
    created_at: datetime
    modified_at: datetime | None


class NotificationStatsRead(ApiModel):
    total_subscriptions: int
    active_subscriptions: int
    total_logs: int
    successful_logs: int
    failed_notifications: int


class SubscriptionStatsRead(ApiModel):
    subscription_id: UUID
    event_type: str
    webhook_url: str | None
    is_active: bool
    total_notifications: int
    successful_notifications: int
    failed_notifications: int
    last_modified: datetime | None
