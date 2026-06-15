using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

/// <summary>
/// Gestión de licencias Office 365 vía Microsoft Graph.
/// Servicio independiente de IAzureManagementService.
/// Prerequisito para asignar licencias: el usuario debe tener UsageLocation configurado.
/// </summary>
public interface IMicrosoftLicenseService
{
    /// <summary>Retorna todos los SKUs adquiridos en el tenant con disponibilidad.</summary>
    Task<IReadOnlyList<SubscribedSkuDto>> GetSubscribedSkusAsync(CancellationToken ct = default);

    /// <summary>Retorna las licencias actualmente asignadas al usuario.</summary>
    Task<IReadOnlyList<UserLicenseDto>> GetUserLicensesAsync(string upn, CancellationToken ct = default);

    /// <summary>
    /// Asigna una licencia por SkuPartNumber (ej: STANDARDWOFFPACK_FACULTY).
    /// Primero configura UsageLocation si el countryCode es provisto.
    /// Lanza InvalidOperationException si no quedan unidades disponibles.
    /// </summary>
    Task<LicenseOperationResult> AssignLicenseAsync(string upn, string skuPartNumber, string countryCode = "EC", CancellationToken ct = default);

    /// <summary>Quita una licencia al usuario por SkuPartNumber.</summary>
    Task<LicenseOperationResult> RemoveLicenseAsync(string upn, string skuPartNumber, CancellationToken ct = default);

    /// <summary>
    /// Asigna la licencia estándar de empleado (Docente / Administrativo).
    /// El SKU se lee desde auth.tbl_AppParams con nemónico "lic:employee".
    /// </summary>
    Task<LicenseOperationResult> AssignEmployeeLicenseAsync(string upn, string countryCode = "EC", CancellationToken ct = default);

    /// <summary>
    /// Configura el UsageLocation del usuario en Entra (requisito previo para asignar licencias).
    /// </summary>
    Task SetUsageLocationAsync(string upn, string countryCode, CancellationToken ct = default);

    /// <summary>Resuelve el SkuId (GUID) a partir del SkuPartNumber consultando subscribedSkus.</summary>
    Task<Guid?> GetSkuIdByPartNumberAsync(string skuPartNumber, CancellationToken ct = default);
}
