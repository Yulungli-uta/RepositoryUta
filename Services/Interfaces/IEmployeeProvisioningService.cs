using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

/// <summary>
/// Orquesta el ciclo de vida completo de aprovisionamiento de un empleado HR:
/// AD Local → Entra Connect sync → licencia O365.
/// Todos los métodos son idempotentes respecto a HrEmployeeId: si ya existe un
/// registro activo para el empleado, retornan el existente sin duplicar.
/// </summary>
public interface IEmployeeProvisioningService
{
    /// <summary>Aprovisiona un único empleado. Retorna el estado inmediato tras la creación en AD Local.</summary>
    Task<UserProvisioningDto> ProvisionAsync(ProvisionEmployeeRequest req, CancellationToken ct = default);

    /// <summary>
    /// Aprovisiona múltiples empleados en paralelo (máx. 5 concurrentes para no saturar AD).
    /// Los errores individuales no abortan el lote completo.
    /// </summary>
    Task<IReadOnlyList<BulkProvisioningResult>> ProvisionBulkAsync(
        IEnumerable<ProvisionEmployeeRequest> requests,
        CancellationToken ct = default);

    /// <summary>Retorna el estado actual de un registro de aprovisionamiento por Id.</summary>
    Task<UserProvisioningDto?> GetStatusAsync(Guid id, CancellationToken ct = default);

    /// <summary>Retorna todos los registros con paginación y filtro opcional por ProvisioningStatusId.</summary>
    Task<PagedResult<UserProvisioningDto>> ListAsync(
        int page, int pageSize,
        int? statusId = null,
        CancellationToken ct = default);

    /// <summary>
    /// Reintenta el aprovisionamiento desde el punto de falla.
    /// Para <c>LocalAdFailed</c> se requiere <paramref name="newInitialPassword"/> no vacío (AD creation).
    /// Para <c>LicenseFailed</c> delega a <see cref="CheckAndCompleteProvisioningAsync"/> (no recrea en AD).
    /// </summary>
    Task<UserProvisioningDto?> RetryAsync(Guid id, string? newInitialPassword = null, CancellationToken ct = default);

    /// <summary>
    /// Verifica si el usuario ya sincronizó con Entra ID y, si es así,
    /// asigna la licencia O365 correspondiente al tipo de empleado.
    /// Transición de estados: PendingEntraSync → SyncedInEntra → LicenseAssigned / LicenseFailed.
    /// </summary>
    Task<UserProvisioningDto?> CheckAndCompleteProvisioningAsync(Guid id, CancellationToken ct = default);

    /// <summary>
    /// Procesa todos los registros en estado PendingEntraSync o SyncedInEntra
    /// (máx. 3 concurrentes para respetar los rate limits de Graph API).
    /// Ideal para ejecutar desde el admin dashboard o una tarea programada.
    /// </summary>
    Task<CompletePendingResult> CompletePendingAsync(CancellationToken ct = default);

    /// <summary>
    /// Restablece la contraseña en AD Local para un empleado aprovisionado.
    /// Solo aplica a registros con <see cref="ProvisioningStatus.CreatedInLocalAd"/> en adelante.
    /// Retorna null si el registro no existe o no tiene cuenta AD Local.
    /// </summary>
    Task<PasswordResetResult?> ResetPasswordAsync(Guid id, CancellationToken ct = default);

    /// <summary>
    /// Deshabilita la cuenta institucional de un empleado:
    /// desactiva en AD Local, mueve a OU Inactivos, quita del grupo activo
    /// y pone auth.tbl_Users.IsActive = false.
    /// </summary>
    Task<DisableEmployeeResult> DisableEmployeeAsync(int hrEmployeeId, CancellationToken ct = default);

    /// <summary>
    /// Deshabilita por ID de registro de aprovisionamiento (Guid).
    /// Retorna null si el registro no existe.
    /// </summary>
    Task<DisableEmployeeResult?> DisableByProvisioningIdAsync(Guid provisioningId, CancellationToken ct = default);

    /// <summary>
    /// Deshabilita por GUID del objeto AD Local (LocalAdObjectId).
    /// Retorna null si no existe registro de aprovisionamiento con ese ObjectId.
    /// </summary>
    Task<DisableEmployeeResult?> DisableByAdIdAsync(string adObjectId, CancellationToken ct = default);
}
