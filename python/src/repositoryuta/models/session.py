from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Index, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, BigIntegerPk


class UserSession(Base):
    """auth.tbl_UserSessions.

    SessionId se genera en Python (uuid4), igual que en C# (`= Guid.NewGuid()`
    en la clase, no un default de BD) — ver Data/Repositories/_Specialized.cs
    AuthRepository.CreateSessionAsync.
    """

    __tablename__ = "tbl_UserSessions"
    __table_args__ = (
        Index("ix_tbl_UserSessions_UserId_IsActive_ExpiresAt", "UserId", "IsActive", "ExpiresAt"),
        {"schema": "auth"},
    )

    session_id: Mapped[UUID] = mapped_column("SessionId", Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    # AccessToken no tiene HasMaxLength en la config .NET (nvarchar(max) por convencion).
    access_token: Mapped[str] = mapped_column("AccessToken", Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column("RefreshToken", String(500), nullable=False)
    expires_at: Mapped[datetime] = mapped_column("ExpiresAt", nullable=False)
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    device_info: Mapped[str | None] = mapped_column("DeviceInfo", Text)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", Text)
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )
    status: Mapped[str] = mapped_column(
        "Status", String(16), default="Active", server_default="Active"
    )
    browser_id: Mapped[str | None] = mapped_column("BrowserId", String(128))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(500))
    last_activity_at: Mapped[datetime | None] = mapped_column("LastActivityAt")
    revoked_at: Mapped[datetime | None] = mapped_column("RevokedAt")
    revoked_by: Mapped[str | None] = mapped_column("RevokedBy", String(320))


class FailedLoginAttempt(Base):
    """auth.tbl_FailedLoginAttempts. Solo lectura/insercion, nunca se actualiza."""

    __tablename__ = "tbl_FailedLoginAttempts"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_email: Mapped[str] = mapped_column("UserEmail", String(320), nullable=False)
    # AttemptedAt no tiene HasDefaultValueSql en .NET: lo fija AuthRepository con
    # DateTime.Now (hora local del servidor, no UTC) — se replica igual, sin
    # normalizar a UTC, para no divergir del dato ya almacenado.
    attempted_at: Mapped[datetime] = mapped_column("AttemptedAt", nullable=False)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String(64))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(400))
    reason: Mapped[str | None] = mapped_column("Reason", Text)
    window_bucket: Mapped[datetime | None] = mapped_column("WindowBucket")
