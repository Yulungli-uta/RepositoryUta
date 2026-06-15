namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

/// <summary>
/// Servicio centralizado para registrar eventos de auditoría en AuditLog.
/// </summary>
public interface IAuditService
{
    /// <summary>Registra una acción de auditoría de forma asíncrona.</summary>
    Task LogAsync(
        string action,
        string module,
        string? entityId = null,
        string? oldValues = null,
        string? newValues = null,
        Guid? userId = null);
}
