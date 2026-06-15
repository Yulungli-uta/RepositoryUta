using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class WebSocketConnectionService : IWebSocketConnectionService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<WebSocketConnectionService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public WebSocketConnectionService(
            AuthDbContext context,
            ILogger<WebSocketConnectionService> logger,
            IHttpContextAccessor httpContextAccessor)
        {
            _context             = context;
            _logger              = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null, string? browserId = null)
        {
            try
            {
                var application = await _context.Applications
                    .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (application == null)
                {
                    _logger.LogWarning("Aplicación no encontrada para clientId: {ClientId}", clientId);
                    return;
                }

                Guid? userGuid = null;
                if (!string.IsNullOrEmpty(userId) && Guid.TryParse(userId, out var parsedUserId))
                    userGuid = parsedUserId;

                // Capturar IP y UserAgent del contexto HTTP actual
                var httpContext = _httpContextAccessor.HttpContext;
                var ipAddress   = httpContext?.Connection.RemoteIpAddress?.ToString();
                var userAgent   = httpContext?.Request.Headers.UserAgent.ToString();

                var now = DateTime.UtcNow;
                var existing = await _context.WebSocketConnections
                    .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

                if (existing != null)
                {
                    existing.IsActive    = true;
                    existing.ConnectedAt = now;
                    existing.LastPingAt  = now;
                    existing.UserId      = userGuid ?? existing.UserId;
                    if (!string.IsNullOrEmpty(browserId))   existing.BrowserId  = browserId;
                    if (!string.IsNullOrEmpty(ipAddress))   existing.IpAddress  = ipAddress;
                    if (!string.IsNullOrEmpty(userAgent))   existing.UserAgent  = userAgent;
                }
                else
                {
                    _context.WebSocketConnections.Add(new WebSocketConnection
                    {
                        ApplicationId = application.Id,
                        ConnectionId  = connectionId,
                        UserId        = userGuid,
                        BrowserId     = browserId,
                        IpAddress     = ipAddress,
                        UserAgent     = userAgent,
                        ConnectedAt   = now,
                        LastPingAt    = now,
                        IsActive      = true,
                    });
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Conexión WebSocket registrada: {ConnectionId} para app {ClientId} (browserId={BrowserId})",
                    connectionId, clientId, browserId ?? "null");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando conexión WebSocket {ConnectionId} para app {ClientId}", connectionId, clientId);
            }
        }

        public async Task UnregisterConnectionAsync(string connectionId)
        {
            try
            {
                var connection = await _context.WebSocketConnections
                    .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

                if (connection != null)
                {
                    connection.IsActive = false;
                    connection.DisconnectedAt = DateTime.Now;
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Conexión WebSocket desregistrada: {ConnectionId}", connectionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error desregistrando conexión WebSocket {ConnectionId}", connectionId);
            }
        }

        public async Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId)
        {
            try
            {
                return await _context.WebSocketConnections
                    .Join(_context.Applications, wc => wc.ApplicationId, a => a.Id, (wc, a) => new { wc, a })
                    .Where(x => x.a.ClientId == clientId && x.wc.IsActive && x.a.IsActive && !x.a.IsDeleted)
                    .Select(x => x.wc.ConnectionId)
                    .ToListAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo conexiones activas para {ClientId}", clientId);
                return Enumerable.Empty<string>();
            }
        }

        public async Task<bool> IsConnectionActiveAsync(string connectionId)
        {
            try
            {
                return await _context.WebSocketConnections
                    .AnyAsync(c => c.ConnectionId == connectionId && c.IsActive);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verificando si conexión {ConnectionId} está activa", connectionId);
                return false;
            }
        }

        public async Task UpdateLastPingAsync(string connectionId)
        {
            try
            {
                var connection = await _context.WebSocketConnections
                    .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

                if (connection != null)
                {
                    connection.LastPingAt = DateTime.Now;
                    await _context.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando último ping para {ConnectionId}", connectionId);
            }
        }

        public async Task<int> GetActiveConnectionCountAsync(string clientId)
        {
            try
            {
                return await _context.WebSocketConnections
                    .Join(_context.Applications, wc => wc.ApplicationId, a => a.Id, (wc, a) => new { wc, a })
                    .Where(x => x.a.ClientId == clientId && x.wc.IsActive && x.a.IsActive && !x.a.IsDeleted)
                    .CountAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error contando conexiones activas para {ClientId}", clientId);
                return 0;
            }
        }

        public async Task CleanupInactiveConnectionsAsync(int inactiveMinutes = 60)
        {
            try
            {
                var cutoffTime = DateTime.Now.AddMinutes(-inactiveMinutes);
                var inactive = await _context.WebSocketConnections
                    .Where(c => c.IsActive && (c.LastPingAt == null || c.LastPingAt < cutoffTime))
                    .ToListAsync();

                var now = DateTime.Now;
                foreach (var connection in inactive)
                {
                    connection.IsActive = false;
                    connection.DisconnectedAt = now;
                }

                await _context.SaveChangesAsync();
                _logger.LogInformation("Limpiadas {Count} conexiones WebSocket inactivas", inactive.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error limpiando conexiones WebSocket inactivas");
            }
        }
    }
}
