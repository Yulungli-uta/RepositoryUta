from datetime import datetime
from enum import IntEnum
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import Boolean, Index, Integer, String, Text, Uuid, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base, BigIntegerPk, SoftDeleteMixin


class User(Base, SoftDeleteMixin):
    """auth.tbl_Users. Implementa ISoftDeletable en .NET.

    Id no tiene default ni en C# ni en BD: quien lo crea (UserRegistrationService,
    AzureAdRepository) debe asignar el uuid explicitamente antes de insertar.
    """

    __tablename__ = "tbl_Users"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True)
    email: Mapped[str] = mapped_column("Email", String(320), nullable=False, unique=True)
    display_name: Mapped[str | None] = mapped_column("DisplayName", String(200))
    azure_object_id: Mapped[UUID | None] = mapped_column("AzureObjectId", Uuid)
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )
    last_login: Mapped[datetime | None] = mapped_column("LastLogin")
    user_type: Mapped[str] = mapped_column(
        "UserType", String(16), default="AzureAD", server_default="AzureAD"
    )


class UserEmployee(Base):
    """auth.tbl_UserEmployees. Vincula un User con su empleado real de HR."""

    __tablename__ = "tbl_UserEmployees"
    __table_args__ = (
        Index("ix_tbl_UserEmployees_UserId", "UserId"),
        Index("ix_tbl_UserEmployees_HrEmployeeId", "HrEmployeeId"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    employee_email: Mapped[str] = mapped_column("EmployeeEmail", String(150), nullable=False)
    hr_employee_id: Mapped[int | None] = mapped_column("HrEmployeeId", Integer)
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )
    sync_date: Mapped[datetime | None] = mapped_column("SyncDate")
    notes: Mapped[str | None] = mapped_column("Notes", Text)


class LocalUserCredential(Base):
    """auth.tbl_LocalUserCredentials. PK = UserId (relacion 1:1 con User).

    `implicit_returning=False` replica exactamente `UseSqlOutputClause(false)` de
    .NET: la tabla tiene el trigger `trg_LocalUserCredentials_Audit`, y SQL Server
    no permite la clausula OUTPUT en INSERT/UPDATE/DELETE sobre una tabla con
    trigger (salvo OUTPUT ... INTO). Sin esto, cualquier UPDATE/DELETE fallaria.
    """

    __tablename__ = "tbl_LocalUserCredentials"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth", "implicit_returning": False}

    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, primary_key=True)
    password_hash: Mapped[str] = mapped_column("PasswordHash", String(255), nullable=False)
    # Sin HasDefaultValueSql en .NET: la entidad C# lo fija con un inicializador
    # de campo (`= DateTime.Now`, hora local) al construirse — se replica aqui
    # con `default=` (evaluado por instancia, igual que el inicializador),
    # necesario para que CrudService.create() no intente insertar NULL.
    password_created_at: Mapped[datetime] = mapped_column(
        "PasswordCreatedAt", nullable=False, default=datetime.now
    )
    password_expires_at: Mapped[datetime | None] = mapped_column("PasswordExpiresAt")
    must_change_password: Mapped[bool] = mapped_column(
        "MustChangePassword", Boolean, default=False, server_default=text("0")
    )
    failed_attempts: Mapped[int] = mapped_column(
        "FailedAttempts", Integer, default=0, server_default="0"
    )
    last_failed_attempt: Mapped[datetime | None] = mapped_column("LastFailedAttempt")
    locked_until: Mapped[datetime | None] = mapped_column("LockedUntil")
    is_locked: Mapped[bool] = mapped_column(
        "IsLocked", Boolean, default=False, server_default=text("0")
    )
    two_factor_enabled: Mapped[bool] = mapped_column(
        "TwoFactorEnabled", Boolean, default=False, server_default=text("0")
    )
    two_factor_secret: Mapped[str | None] = mapped_column("TwoFactorSecret", Text)
    security_questions: Mapped[str | None] = mapped_column("SecurityQuestions", Text)


class SecurityToken(Base):
    """auth.tbl_SecurityTokens (reset de password, etc.). Id se genera en Python,
    igual que en C# (`= Guid.NewGuid()` en la clase, no default de BD)."""

    __tablename__ = "tbl_SecurityTokens"
    __table_args__ = (
        Index("ix_tbl_SecurityTokens_ExpiresAt", "ExpiresAt"),
        Index("ix_tbl_SecurityTokens_UserId_TokenType", "UserId", "TokenType"),
        {"schema": "auth"},
    )

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    token_type: Mapped[str] = mapped_column(
        "TokenType", String(20), nullable=False, default="PasswordReset"
    )
    token_hash: Mapped[str] = mapped_column("TokenHash", String(256), nullable=False)
    expires_at: Mapped[datetime] = mapped_column("ExpiresAt", nullable=False)
    is_used: Mapped[bool] = mapped_column("IsUsed", Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )
    additional_data: Mapped[str | None] = mapped_column("AdditionalData", Text)


class PasswordHistory(Base):
    """auth.tbl_PasswordHistory. Solo insercion (sin update)."""

    __tablename__ = "tbl_PasswordHistory"
    __table_args__ = (
        Index("ix_tbl_PasswordHistory_UserId", "UserId"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    password_hash: Mapped[str] = mapped_column("PasswordHash", String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )


class UserAccountLock(Base):
    """auth.tbl_UserAccountLocks."""

    __tablename__ = "tbl_UserAccountLocks"
    __table_args__ = (
        Index("ix_tbl_UserAccountLocks_UserId", "UserId"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    lock_type: Mapped[str] = mapped_column(
        "LockType", String(32), nullable=False, default="FailedAttempts"
    )
    lock_reason: Mapped[str] = mapped_column("LockReason", String(300), nullable=False)
    locked_at: Mapped[datetime] = mapped_column(
        "LockedAt", server_default=text("SYSUTCDATETIME()")
    )
    locked_by: Mapped[str | None] = mapped_column("LockedBy", Text)
    auto_unlock_at: Mapped[datetime | None] = mapped_column("AutoUnlockAt")
    unlocked_at: Mapped[datetime | None] = mapped_column("UnlockedAt")
    unlocked_by: Mapped[str | None] = mapped_column("UnlockedBy", Text)
    is_active: Mapped[bool] = mapped_column(
        "IsActive", Boolean, default=True, server_default=text("1")
    )


class UserActivityLog(Base):
    """auth.tbl_UserActivityLog. Solo insercion."""

    __tablename__ = "tbl_UserActivityLog"
    __table_args__ = (
        Index("ix_tbl_UserActivityLog_UserId_Timestamp", "UserId", "Timestamp"),
        {"schema": "auth"},
    )

    id: Mapped[int] = mapped_column("Id", BigIntegerPk, primary_key=True, autoincrement=True)
    user_id: Mapped[UUID] = mapped_column("UserId", Uuid, nullable=False)
    session_id: Mapped[UUID | None] = mapped_column("SessionId", Uuid)
    activity: Mapped[str] = mapped_column("Activity", String(100), nullable=False)
    activity_details: Mapped[str | None] = mapped_column("ActivityDetails", Text)
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String(64))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(400))
    timestamp: Mapped[datetime] = mapped_column(
        "Timestamp", server_default=text("SYSUTCDATETIME()")
    )
    module_accessed: Mapped[str | None] = mapped_column("ModuleAccessed", String(100))
    action_performed: Mapped[str | None] = mapped_column("ActionPerformed", String(100))


class ProvisioningStatus(IntEnum):
    """Espejo exacto de ProvisioningStatus (Models/Entities/_Entities.cs).

    Los valores coinciden con HR.ref_Types.TypeId (Category='ProvisioningStatus')
    a proposito, para permitir JOINs desde reportes HR — no renumerar.
    """

    REQUESTED = 2001
    CREATED_IN_LOCAL_AD = 2002
    PENDING_ENTRA_SYNC = 2003
    SYNCED_IN_ENTRA = 2004
    LICENSE_ASSIGNED = 2005
    LICENSE_FAILED = 2006
    LOCAL_AD_FAILED = 2007


# nameof(ProvisioningStatus.X) en C# da PascalCase ("CreatedInLocalAd"), no el
# nombre del miembro Python en mayusculas ("CREATED_IN_LOCAL_AD") — este mapeo
# es el unico lugar que debe usarse para persistir ProvisioningStatusName
# (columna leida/comparada por HrBackend y reportes), nunca `status.name`.
PROVISIONING_STATUS_NAMES: dict[ProvisioningStatus, str] = {
    ProvisioningStatus.REQUESTED: "Requested",
    ProvisioningStatus.CREATED_IN_LOCAL_AD: "CreatedInLocalAd",
    ProvisioningStatus.PENDING_ENTRA_SYNC: "PendingEntraSync",
    ProvisioningStatus.SYNCED_IN_ENTRA: "SyncedInEntra",
    ProvisioningStatus.LICENSE_ASSIGNED: "LicenseAssigned",
    ProvisioningStatus.LICENSE_FAILED: "LicenseFailed",
    ProvisioningStatus.LOCAL_AD_FAILED: "LocalAdFailed",
}


class UserProvisioning(Base):
    """auth.tbl_UserProvisioning. Ciclo de vida AD Local -> Entra ID -> O365.

    Id tiene default tanto en C# (`= Guid.NewGuid()`) como en BD (`NEWID()`); EF
    siempre manda el valor generado en C#, por eso aqui se replica con
    `default=uuid4` (evaluado en Python), no delegando al default de BD.
    """

    __tablename__ = "tbl_UserProvisioning"
    __table_args__ = (
        Index("ix_tbl_UserProvisioning_HrEmployeeId", "HrEmployeeId"),
        Index("ix_tbl_UserProvisioning_Email", "Email"),
        Index("ix_tbl_UserProvisioning_ProvisioningStatusId", "ProvisioningStatusId"),
        Index("ix_tbl_UserProvisioning_AuthUserId", "AuthUserId"),
        {"schema": "auth"},
    )

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True, default=uuid4)

    hr_employee_id: Mapped[int] = mapped_column("HrEmployeeId", Integer, nullable=False)
    email: Mapped[str] = mapped_column("Email", String(320), nullable=False)
    display_name: Mapped[str] = mapped_column("DisplayName", String(256), nullable=False)
    given_name: Mapped[str | None] = mapped_column("GivenName", String(128))
    surname: Mapped[str | None] = mapped_column("Surname", String(128))

    department_id: Mapped[int | None] = mapped_column("DepartmentId", Integer)
    department_name: Mapped[str | None] = mapped_column("DepartmentName", String(256))

    job_title: Mapped[str | None] = mapped_column("JobTitle", String(256))

    employee_type_id: Mapped[int] = mapped_column("EmployeeTypeId", Integer, nullable=False)
    employee_type_name: Mapped[str | None] = mapped_column("EmployeeTypeName", String(128))

    provisioning_status_id: Mapped[int] = mapped_column(
        "ProvisioningStatusId", Integer, default=int(ProvisioningStatus.REQUESTED)
    )
    provisioning_status_name: Mapped[str | None] = mapped_column(
        "ProvisioningStatusName",
        String(64),
        default=PROVISIONING_STATUS_NAMES[ProvisioningStatus.REQUESTED],
    )

    auth_user_id: Mapped[UUID | None] = mapped_column("AuthUserId", Uuid)
    local_ad_object_id: Mapped[str | None] = mapped_column("LocalAdObjectId", String(128))
    entra_object_id: Mapped[str | None] = mapped_column("EntraObjectId", String(128))
    license_sku_id: Mapped[str | None] = mapped_column("LicenseSkuId", String(256))

    provisioned_at: Mapped[datetime | None] = mapped_column("ProvisionedAt")
    license_assigned_at: Mapped[datetime | None] = mapped_column("LicenseAssignedAt")
    last_checked_at: Mapped[datetime | None] = mapped_column("LastCheckedAt")

    error_message: Mapped[str | None] = mapped_column("ErrorMessage", Text)
    requested_by: Mapped[str | None] = mapped_column("RequestedBy", String(320))
    source_reference: Mapped[str | None] = mapped_column("SourceReference", String(128))

    created_at: Mapped[datetime] = mapped_column(
        "CreatedAt", server_default=text("SYSUTCDATETIME()")
    )
    updated_at: Mapped[datetime | None] = mapped_column("UpdatedAt")
