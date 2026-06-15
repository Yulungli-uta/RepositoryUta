using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

/// <summary>
/// Gestión de sesiones activas de usuarios y clientes API.
/// Permite listar, revocar sesiones de usuario y administrar clientes API.
/// </summary>
public interface ISessionManagementService
{
    // ── Sesiones de usuario ────────────────────────────────────────────────────

    /// <summary>Retorna todas las sesiones de usuario activas y no expiradas.</summary>
    Task<IReadOnlyList<ActiveSessionDto>> GetActiveSessionsAsync(CancellationToken ct = default);

    /// <summary>
    /// Revoca una sesión: la marca como inactiva en BD y envía ForceLogout
    /// via SignalR al navegador del usuario si tiene conexión WS activa.
    /// </summary>
    Task<RevokeSessionResultDto> RevokeSessionAsync(Guid sessionId, string revokedBy, CancellationToken ct = default);

    /// <summary>Revoca todas las sesiones activas de un usuario específico.</summary>
    Task<int> RevokeAllUserSessionsAsync(Guid userId, string revokedBy, CancellationToken ct = default);

    // ── Clientes API ───────────────────────────────────────────────────────────

    /// <summary>Retorna todos los clientes API no eliminados con estadísticas de uso.</summary>
    Task<IReadOnlyList<ActiveApiClientDto>> GetActiveApiClientsAsync(CancellationToken ct = default);

    /// <summary>
    /// Activa o suspende un cliente API.
    /// Al suspender, actualiza SuspendedAt / SuspendedBy.
    /// </summary>
    Task<ToggleClientResultDto> ToggleClientAsync(Guid applicationId, string changedBy, CancellationToken ct = default);

    /// <summary>
    /// Rota el ClientSecret de una aplicación.
    /// Devuelve el nuevo secret en texto plano — solo se puede ver en este momento.
    /// </summary>
    Task<RotateSecretResultDto> RotateSecretAsync(Guid applicationId, string rotatedBy, CancellationToken ct = default);
}
