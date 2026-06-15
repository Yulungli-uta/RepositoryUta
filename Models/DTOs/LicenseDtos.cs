namespace WsSeguUta.AuthSystem.API.Models.DTOs;

// ─── SKUs del tenant ──────────────────────────────────────────────────────────

/// <summary>Información de un SKU de licencia disponible en el tenant.</summary>
public record SubscribedSkuDto(
    /// <summary>GUID del SKU en Microsoft Entra (usado para asignar/quitar).</summary>
    Guid SkuId,

    /// <summary>Código de producto legible, ej: STANDARDWOFFPACK_FACULTY.</summary>
    string SkuPartNumber,

    /// <summary>Estado del SKU: Enabled, Warning, Suspended.</summary>
    string? CapabilityStatus,

    /// <summary>Total de licencias adquiridas.</summary>
    int? PrepaidUnitsEnabled,

    /// <summary>Licencias actualmente asignadas a usuarios.</summary>
    int? ConsumedUnits,

    /// <summary>Licencias disponibles para asignar (prepaid - consumed).</summary>
    int? AvailableUnits
);

// ─── Licencias de un usuario ──────────────────────────────────────────────────

/// <summary>Licencia asignada a un usuario en Microsoft Entra.</summary>
public record UserLicenseDto(
    Guid SkuId,
    string? SkuPartNumber
);

// ─── Request / Response de asignación ─────────────────────────────────────────

/// <summary>Request para asignar o quitar una licencia a un usuario.</summary>
public record LicenseAssignRequest(
    /// <summary>UPN del usuario (ej: juan.perez@uta.edu.ec).</summary>
    string Upn,

    /// <summary>Código del SKU a asignar, ej: STANDARDWOFFPACK_FACULTY.</summary>
    string SkuPartNumber,

    /// <summary>Código de país ISO 3166 para UsageLocation (ej: EC). Default EC.</summary>
    string CountryCode = "EC"
);

/// <summary>Request para asignar la licencia estándar de empleado (lic:employee).</summary>
public record LicenseAssignEmployeeRequest(
    string Upn,
    string CountryCode = "EC"
);

/// <summary>Resultado de una operación de asignación/remoción de licencia.</summary>
public record LicenseOperationResult(
    bool Success,
    string Upn,
    string? SkuPartNumber,
    Guid? SkuId,
    string? Message
);
