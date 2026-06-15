using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Hubs;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

/// <summary>
/// Implementación de gestión de sesiones activas de usuarios y clientes API.
/// </summary>
public class SessionManagementService : ISessionManagementService
{
    private readonly AuthDbContext _context;
    private readonly IHubContext<NotificationHub> _hub;
    private readonly ITokenService _tokenService;
    private readonly IAuditService _audit;
    private readonly ILogger<SessionManagementService> _logger;

    public SessionManagementService(
        AuthDbContext context,
        IHubContext<NotificationHub> hub,
        ITokenService tokenService,
        IAuditService audit,
        ILogger<SessionManagementService> logger)
    {
        _context = context;
        _hub = hub;
        _tokenService = tokenService;
        _audit = audit;
        _logger = logger;
    }

    // ── Sesiones de usuario ────────────────────────────────────────────────────

    /// <inheritdoc/>
    public async Task<IReadOnlyList<ActiveSessionDto>> GetActiveSessionsAsync(CancellationToken ct = default)
    {
        var rows = await _context.VwActiveSessions
            .AsNoTracking()
            .OrderByDescending(s => s.LoginAt)
            .ToListAsync(ct);

        return rows.Select(s => new ActiveSessionDto
        {
            SessionId            = s.SessionId,
            UserId               = s.UserId,
            Email                = s.Email,
            DisplayName          = s.DisplayName,
            UserType             = s.UserType,
            IpAddress            = s.IpAddress,
            UserAgent            = s.UserAgent,
            BrowserId            = s.BrowserId,
            LoginAt              = s.LoginAt,
            LastActivityAt       = s.LastActivityAt,
            ExpiresAt            = s.ExpiresAt,
            Status               = s.Status,
            IsWebSocketConnected = s.WsIsActive == true,
            WsLastPing           = s.WsLastPing,
        }).ToList();
    }

    /// <inheritdoc/>
    public async Task<RevokeSessionResultDto> RevokeSessionAsync(Guid sessionId, string revokedBy, CancellationToken ct = default)
    {
        var session = await _context.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == sessionId && s.IsActive, ct)
            ?? throw new InvalidOperationException($"Sesión {sessionId} no encontrada o ya inactiva.");

        // 1. Marcar sesión como revocada en BD
        session.IsActive      = false;
        session.Status        = "Revoked";
        session.RevokedAt     = DateTime.UtcNow;
        session.RevokedBy     = revokedBy;

        // 2. Buscar conexión WS activa vinculada por BrowserId
        bool notified = false;
        if (!string.IsNullOrEmpty(session.BrowserId))
        {
            var wsConn = await _context.WebSocketConnections
                .Where(w => w.BrowserId == session.BrowserId && w.IsActive)
                .FirstOrDefaultAsync(ct);

            if (wsConn != null)
            {
                try
                {
                    await _hub.Clients.Client(wsConn.ConnectionId)
                        .SendAsync("ReceiveNotification", new
                        {
                            eventType  = "ForceLogout",
                            sessionId  = sessionId.ToString(),
                            reason     = "Sesión revocada por administrador",
                            timestamp  = DateTime.UtcNow.ToString("o"),
                            revokedBy,
                        }, ct);
                    notified = true;
                    _logger.LogInformation("ForceLogout enviado a connectionId {ConnId} (browserId {BId})",
                        wsConn.ConnectionId, session.BrowserId);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "No se pudo enviar ForceLogout a {ConnId}", wsConn.ConnectionId);
                }
            }
        }

        await _context.SaveChangesAsync(ct);

        await _audit.LogAsync(
            action:    "SessionRevoked",
            module:    "Sessions",
            entityId:  sessionId.ToString(),
            oldValues: System.Text.Json.JsonSerializer.Serialize(new { session.UserId, session.IpAddress, session.BrowserId }),
            newValues: System.Text.Json.JsonSerializer.Serialize(new { RevokedBy = revokedBy, RevokedAt = session.RevokedAt, WsNotified = notified }));

        return new RevokeSessionResultDto
        {
            SessionId   = sessionId,
            WasNotified = notified,
            Message     = notified
                ? "Sesión revocada y usuario notificado en tiempo real."
                : "Sesión revocada. El usuario será desconectado en su próxima petición.",
        };
    }

    /// <inheritdoc/>
    public async Task<int> RevokeAllUserSessionsAsync(Guid userId, string revokedBy, CancellationToken ct = default)
    {
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == userId && s.IsActive)
            .ToListAsync(ct);

        if (sessions.Count == 0) return 0;

        int notified = 0;
        foreach (var session in sessions)
        {
            session.IsActive  = false;
            session.Status    = "Revoked";
            session.RevokedAt = DateTime.UtcNow;
            session.RevokedBy = revokedBy;

            if (!string.IsNullOrEmpty(session.BrowserId))
            {
                var wsConn = await _context.WebSocketConnections
                    .Where(w => w.BrowserId == session.BrowserId && w.IsActive)
                    .FirstOrDefaultAsync(ct);

                if (wsConn != null)
                {
                    try
                    {
                        await _hub.Clients.Client(wsConn.ConnectionId)
                            .SendAsync("ReceiveNotification", new
                            {
                                eventType = "ForceLogout",
                                sessionId = session.SessionId.ToString(),
                                reason    = "Todas las sesiones revocadas por administrador",
                                timestamp = DateTime.UtcNow.ToString("o"),
                                revokedBy,
                            }, ct);
                        notified++;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "No se pudo enviar ForceLogout a {ConnId}", wsConn.ConnectionId);
                    }
                }
            }
        }

        await _context.SaveChangesAsync(ct);

        await _audit.LogAsync(
            action:    "AllSessionsRevoked",
            module:    "Sessions",
            entityId:  userId.ToString(),
            newValues: System.Text.Json.JsonSerializer.Serialize(new { RevokedCount = sessions.Count, NotifiedCount = notified, RevokedBy = revokedBy }));

        return sessions.Count;
    }

    // ── Clientes API ───────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public async Task<IReadOnlyList<ActiveApiClientDto>> GetActiveApiClientsAsync(CancellationToken ct = default)
    {
        var rows = await _context.VwActiveApiClients
            .AsNoTracking()
            .OrderByDescending(a => a.LastUsedAt)
            .ThenBy(a => a.Name)
            .ToListAsync(ct);

        return rows.Select(a => new ActiveApiClientDto
        {
            Id               = a.Id,
            Name             = a.Name,
            ClientId         = a.ClientId,
            Description      = a.Description,
            IsActive         = a.IsActive,
            CreatedAt        = a.CreatedAt,
            CreatedBy        = a.CreatedBy,
            LastUsedAt       = a.LastUsedAt,
            SecretRotatedAt  = a.SecretRotatedAt,
            SecretRotatedBy  = a.SecretRotatedBy,
            SuspendedAt      = a.SuspendedAt,
            SuspendedBy      = a.SuspendedBy,
            CallsLast24h     = a.CallsLast24h,
            LastIpAddress    = a.LastIpAddress,
            LastUserAgent    = a.LastUserAgent,
        }).ToList();
    }

    /// <inheritdoc/>
    public async Task<ToggleClientResultDto> ToggleClientAsync(Guid applicationId, string changedBy, CancellationToken ct = default)
    {
        var app = await _context.Applications
            .FirstOrDefaultAsync(a => a.Id == applicationId && !a.IsDeleted, ct)
            ?? throw new InvalidOperationException($"Aplicación {applicationId} no encontrada.");

        app.IsActive    = !app.IsActive;
        app.ModifiedAt  = DateTime.UtcNow;
        app.ModifiedBy  = changedBy;

        if (!app.IsActive)
        {
            app.SuspendedAt = DateTime.UtcNow;
            app.SuspendedBy = changedBy;
        }
        else
        {
            app.SuspendedAt = null;
            app.SuspendedBy = null;
        }

        await _context.SaveChangesAsync(ct);

        await _audit.LogAsync(
            action:    app.IsActive ? "ClientActivated" : "ClientSuspended",
            module:    "Applications",
            entityId:  applicationId.ToString(),
            newValues: System.Text.Json.JsonSerializer.Serialize(new { app.ClientId, app.IsActive, ChangedBy = changedBy }));

        return new ToggleClientResultDto
        {
            ApplicationId = applicationId,
            ClientId      = app.ClientId,
            IsActive      = app.IsActive,
            Message       = app.IsActive ? "Cliente API activado." : "Cliente API suspendido. Todos los tokens actuales serán rechazados.",
        };
    }

    /// <inheritdoc/>
    public async Task<RotateSecretResultDto> RotateSecretAsync(Guid applicationId, string rotatedBy, CancellationToken ct = default)
    {
        var app = await _context.Applications
            .FirstOrDefaultAsync(a => a.Id == applicationId && !a.IsDeleted, ct)
            ?? throw new InvalidOperationException($"Aplicación {applicationId} no encontrada.");

        // Generar nuevo secret aleatorio (32 bytes → 43 chars base64url)
        var newSecret     = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))
                              .Replace("+", "-").Replace("/", "_").TrimEnd('=');
        var newSecretHash = _tokenService.Hash(newSecret);

        app.ClientSecretHash = newSecretHash;
        app.SecretRotatedAt  = DateTime.UtcNow;
        app.SecretRotatedBy  = rotatedBy;
        app.ModifiedAt       = DateTime.UtcNow;
        app.ModifiedBy       = rotatedBy;

        await _context.SaveChangesAsync(ct);

        await _audit.LogAsync(
            action:    "SecretRotated",
            module:    "Applications",
            entityId:  applicationId.ToString(),
            newValues: System.Text.Json.JsonSerializer.Serialize(new { app.ClientId, RotatedBy = rotatedBy, RotatedAt = app.SecretRotatedAt }));

        _logger.LogInformation("Secret rotado para aplicación {ClientId} por {RotatedBy}", app.ClientId, rotatedBy);

        return new RotateSecretResultDto
        {
            ApplicationId   = applicationId,
            ClientId        = app.ClientId,
            NewClientSecret = newSecret,
            RotatedAt       = app.SecretRotatedAt!.Value,
        };
    }
}
