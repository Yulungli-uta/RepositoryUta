namespace WsSeguUta.AuthSystem.API.Models.DTOs;

// ─── Request ──────────────────────────────────────────────────────────────────

/// <summary>Datos necesarios para aprovisionar un empleado HR en AD Local → Entra → O365.</summary>
public record ProvisionEmployeeRequest(
    /// <summary>EmployeeId de HrBackend (soft FK cross-DB).</summary>
    int HrEmployeeId,

    string DisplayName,
    string GivenName,
    string Surname,

    /// <summary>Contraseña inicial; debe cumplir la política de complejidad de AD.</summary>
    string InitialPassword,

    /// <summary>TypeId de HR.ref_Types (1=Docente, 2=Administrativo, 3=Trabajador).</summary>
    int EmployeeTypeId,

    string? EmployeeTypeName = null,
    int? DepartmentId = null,
    string? DepartmentName = null,
    string? JobTitle = null,

    /// <summary>Referencia al origen que disparó el aprovisionamiento, ej: "Contract:1234".</summary>
    string? SourceReference = null,

    bool ForcePasswordChange = true,

    /// <summary>Correo personal al que HR notificará las credenciales. No se usa como UPN institucional.</summary>
    string? PersonalEmail = null,

    /// <summary>Email sugerido. IGNORADO — RepositoryUta genera el email institucional internamente (iniciales.apellido@dominio).</summary>
    string? Email = null,

    /// <summary>Cédula/identificación del empleado. Se persiste como atributo employeeID en AD Local.</summary>
    string? IdCard = null
);

// ─── Response ─────────────────────────────────────────────────────────────────

/// <summary>Estado completo de un registro de aprovisionamiento.</summary>
public record UserProvisioningDto(
    Guid Id,
    int HrEmployeeId,
    string Email,
    string DisplayName,
    string? GivenName,
    string? Surname,
    int? DepartmentId,
    string? DepartmentName,
    string? JobTitle,
    int EmployeeTypeId,
    string? EmployeeTypeName,
    int ProvisioningStatusId,
    string? ProvisioningStatusName,
    Guid? AuthUserId,
    string? LocalAdObjectId,
    string? EntraObjectId,
    string? LicenseSkuId,
    DateTime? ProvisionedAt,
    DateTime? LicenseAssignedAt,
    DateTime? LastCheckedAt,
    string? ErrorMessage,
    string? RequestedBy,
    string? SourceReference,
    DateTime CreatedAt,
    DateTime? UpdatedAt,
    /// <summary>
    /// Aviso no bloqueante. Presente cuando el aprovisionamiento fue exitoso pero
    /// ocurrió algo que el administrador debe conocer, ej: el CN fue ajustado
    /// automáticamente porque ya existía otro usuario con el mismo nombre en AD.
    /// Null = sin avisos.
    /// </summary>
    string? Warning = null
);

// ─── Bulk ──────────────────────────────────────────────────────────────────────

/// <summary>Resultado individual dentro de una operación de aprovisionamiento masivo.</summary>
public record BulkProvisioningResult(
    int HrEmployeeId,
    string Email,
    bool Success,
    UserProvisioningDto? Provisioning,
    string? Error
);

/// <summary>Resumen de la operación complete-pending sobre registros en PendingEntraSync/SyncedInEntra.</summary>
public record CompletePendingResult(
    int TotalProcessed,
    int LicenseAssigned,
    int StillPending,
    int Failed,
    IReadOnlyList<UserProvisioningDto> Results
);

/// <summary>Cuerpo del endpoint PATCH /provisioning/employees/{id}/retry para LocalAdFailed.</summary>
public record RetryProvisioningRequest(
    /// <summary>Nueva contraseña inicial. Requerida solo cuando el estado es LocalAdFailed.</summary>
    string? InitialPassword = null
);

/// <summary>Resultado de deshabilitar la cuenta institucional de un empleado.</summary>
public record DisableEmployeeResult(
    bool Success,
    int HrEmployeeId,
    string? Email,
    string? ErrorMessage
);

/// <summary>Resultado de un restablecimiento de contraseña en AD Local para un empleado aprovisionado.</summary>
public record PasswordResetResult(
    Guid ProvisioningId,
    int HrEmployeeId,
    string Email,
    /// <summary>Contraseña temporal generada. Mostrar solo al administrador y registrar en auditoria.</summary>
    string NewTemporaryPassword,
    string Message
);
