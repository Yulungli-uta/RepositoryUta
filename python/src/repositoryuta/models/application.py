from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Index, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, BigIntegerPk


class Application(Base):
    """auth.tbl_Applications (centralizador: apps cliente con client_id/secret).

    Id se genera en Python (uuid4), igual que en C# (`= Guid.NewGuid()`).
    CreatedAt/ModifiedAt NO tienen default de BD en .NET (a diferencia de casi
    todo lo demas en este esquema) — solo el initializer `= DateTime.Now` del
    lado C#, hora local del servidor. Se replica igual con `default=` en
    Python, sin agregar un `server_default` que el .NET real no tiene.
    """

    __tablename__ = "tbl_Applications"
    __table_args__ = (
        Index("ix_tbl_Applications_ClientId", "ClientId"),
        {"schema": "auth"},
    )

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column("Name", Text, nullable=False)
    client_id: Mapped[str] = mapped_column("ClientId", Text, nullable=False)
    client_secret_hash: Mapped[str] = mapped_column("ClientSecretHash", Text, nullable=False)
    description: Mapped[str | None] = mapped_column("Description", Text)
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    created_at: Mapped[datetime] = mapped_column("CreatedAt", default=datetime.now)
    created_by: Mapped[str | None] = mapped_column("CreatedBy", Text)
    modified_at: Mapped[datetime | None] = mapped_column("ModifiedAt", default=datetime.now)
    modified_by: Mapped[str | None] = mapped_column("ModifiedBy", Text)
    is_deleted: Mapped[bool] = mapped_column(
        "IsDeleted", Boolean, default=False, server_default=text("0")
    )
    last_used_at: Mapped[datetime | None] = mapped_column("LastUsedAt")
    secret_rotated_at: Mapped[datetime | None] = mapped_column("SecretRotatedAt")
    secret_rotated_by: Mapped[str | None] = mapped_column("SecretRotatedBy", String(320))
    suspended_at: Mapped[datetime | None] = mapped_column("SuspendedAt")
    suspended_by: Mapped[str | None] = mapped_column("SuspendedBy", String(320))


class LegacyAuthLog(Base):
    """auth.tbl_LegacyAuthLog. Sin clase de configuracion propia en .NET — mapeo
    inline minimo en AuthDbContext.OnModelCreating (solo ToTable + Ignore(AuthType),
    el resto por convencion EF). `AuthType` existe en la entidad C# pero NO en la
    tabla real: a proposito no se incluye ese campo aqui tampoco.
    """

    __tablename__ = "tbl_LegacyAuthLog"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    application_id: Mapped[UUID] = mapped_column("ApplicationId", Uuid, nullable=False)
    user_id: Mapped[UUID | None] = mapped_column("UserId", Uuid)
    user_email: Mapped[str] = mapped_column("UserEmail", Text, nullable=False)
    auth_result: Mapped[str] = mapped_column("AuthResult", Text, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column("FailureReason", Text)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", Text)
    user_agent: Mapped[str | None] = mapped_column("UserAgent", Text)
    response_time: Mapped[int | None] = mapped_column("ResponseTime")
    created_at: Mapped[datetime] = mapped_column("CreatedAt", default=datetime.now)
