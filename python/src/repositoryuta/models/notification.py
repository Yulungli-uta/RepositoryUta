from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, BigIntegerPk


class NotificationSubscription(Base):
    """auth.tbl_NotificationSubscriptions. Id se genera en Python (uuid4), igual
    que en C# (`= Guid.NewGuid()`). CreatedAt sin default de BD, solo el
    initializer `= DateTime.Now` del lado C# (mismo caso que Application)."""

    __tablename__ = "tbl_NotificationSubscriptions"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True, default=uuid4)
    application_id: Mapped[UUID] = mapped_column("ApplicationId", Uuid, nullable=False)
    event_type: Mapped[str] = mapped_column("EventType", Text, nullable=False)
    webhook_url: Mapped[str | None] = mapped_column("WebhookUrl", Text)
    secret_key: Mapped[str | None] = mapped_column("SecretKey", Text)
    notification_type: Mapped[str] = mapped_column(
        "NotificationType", Text, default="webhook"
    )
    web_socket_group_name: Mapped[str | None] = mapped_column("WebSocketGroupName", Text)
    require_authentication: Mapped[bool | None] = mapped_column(
        "RequireAuthentication", Boolean, default=True
    )
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    created_at: Mapped[datetime] = mapped_column("CreatedAt", default=datetime.now)
    created_by: Mapped[str | None] = mapped_column("CreatedBy", Text)
    modified_at: Mapped[datetime | None] = mapped_column("ModifiedAt")
    modified_by: Mapped[str | None] = mapped_column("ModifiedBy", Text)


class NotificationLog(Base):
    """auth.tbl_NotificationLogs. Sin clase de configuracion propia en .NET
    (solo ToTable, resto por convencion) — solo insercion."""

    __tablename__ = "tbl_NotificationLogs"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    subscription_id: Mapped[UUID] = mapped_column("SubscriptionId", Uuid, nullable=False)
    event_type: Mapped[str] = mapped_column("EventType", Text, nullable=False)
    user_id: Mapped[UUID | None] = mapped_column("UserId", Uuid)
    webhook_url: Mapped[str | None] = mapped_column("WebhookUrl", Text)
    http_status_code: Mapped[int | None] = mapped_column("HttpStatusCode")
    response_body: Mapped[str | None] = mapped_column("ResponseBody", Text)
    response_time: Mapped[int | None] = mapped_column("ResponseTime")
    is_success: Mapped[bool] = mapped_column("IsSuccess", Boolean, default=False)
    error_message: Mapped[str | None] = mapped_column("ErrorMessage", Text)
    created_at: Mapped[datetime] = mapped_column("CreatedAt", default=datetime.now)
