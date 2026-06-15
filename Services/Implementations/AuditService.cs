using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

/// <summary>
/// Implementación del servicio de auditoría.
/// Escribe en tbl_AuditLogs usando el repositorio genérico.
/// </summary>
public class AuditService : IAuditService
{
    private readonly IGenericRepository<AuditLog> _auditRepo;
    private readonly IHttpContextAccessor _http;

    public AuditService(IGenericRepository<AuditLog> auditRepo, IHttpContextAccessor http)
    {
        _auditRepo = auditRepo;
        _http      = http;
    }

    /// <inheritdoc/>
    public async Task LogAsync(
        string action,
        string module,
        string? entityId   = null,
        string? oldValues  = null,
        string? newValues  = null,
        Guid?   userId     = null)
    {
        var resolvedUserId = userId ?? ResolveCurrentUserId();
        var context        = _http.HttpContext;

        var entry = new AuditLog
        {
            Action     = action,
            Module     = module,
            EntityId   = entityId,
            OldValues  = oldValues,
            NewValues  = newValues,
            UserId     = resolvedUserId,
            IpAddress  = context?.Connection.RemoteIpAddress?.ToString(),
            UserAgent  = context?.Request.Headers.UserAgent.ToString(),
            Timestamp  = DateTime.UtcNow,
        };

        await _auditRepo.AddAsync(entry);
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    private Guid? ResolveCurrentUserId()
    {
        var raw = _http.HttpContext?.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? _http.HttpContext?.User?.FindFirst("sub")?.Value;

        return Guid.TryParse(raw, out var id) ? id : null;
    }
}
