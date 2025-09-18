using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Hubs
{
    /// <summary>
    /// Hub de SignalR para notificaciones en tiempo real
    /// Maneja conexiones WebSocket para notificaciones de login de Office365
    /// </summary>
    public class NotificationHub : Hub
    {
        private readonly IWebSocketConnectionService _connectionService;
        private readonly ILogger<NotificationHub> _logger;

        public NotificationHub(IWebSocketConnectionService connectionService, ILogger<NotificationHub> logger)
        {
            _connectionService = connectionService;
            _logger = logger;
        }

        /// <summary>
        /// Unirse al grupo de una aplicación específica para recibir notificaciones
        /// </summary>
        /// <param name="clientId">ID de la aplicación cliente</param>
        /// <param name="userId">ID del usuario (opcional)</param>
        public async Task JoinApplicationGroup(string clientId, string? userId = null)
        {
            try
            {
                Console.WriteLine($"*******************Client {Context.ConnectionId} joining group for application {clientId} with user {userId ?? "anonymous"}");
                // Unirse al grupo de la aplicación
                await Groups.AddToGroupAsync(Context.ConnectionId, $"app_{clientId}");
                
                // Registrar la conexión en la base de datos
                await _connectionService.RegisterConnectionAsync(Context.ConnectionId, clientId, userId);
                
                _logger.LogInformation("Client {ConnectionId} joined application group {ClientId} with user {UserId}", 
                    Context.ConnectionId, clientId, userId ?? "anonymous");

                // Confirmar al cliente que se unió exitosamente
                await Clients.Caller.SendAsync("JoinedGroup", new { 
                    clientId, 
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.UtcNow,
                    message = $"Successfully joined notifications for {clientId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error joining application group {ClientId} for connection {ConnectionId}", 
                    clientId, Context.ConnectionId);
                
                await Clients.Caller.SendAsync("Error", new { 
                    message = "Failed to join application group",
                    error = ex.Message 
                });
            }
        }

        /// <summary>
        /// Salir del grupo de una aplicación
        /// </summary>
        /// <param name="clientId">ID de la aplicación cliente</param>
        public async Task LeaveApplicationGroup(string clientId)
        {
            try
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"app_{clientId}");
                
                _logger.LogInformation("Client {ConnectionId} left application group {ClientId}", 
                    Context.ConnectionId, clientId);

                await Clients.Caller.SendAsync("LeftGroup", new { 
                    clientId, 
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.UtcNow,
                    message = $"Successfully left notifications for {clientId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error leaving application group {ClientId} for connection {ConnectionId}", 
                    clientId, Context.ConnectionId);
            }
        }

        /// <summary>
        /// Ping para mantener la conexión activa
        /// </summary>
        public async Task Ping()
        {
            try
            {
                await _connectionService.UpdateLastPingAsync(Context.ConnectionId);
                await Clients.Caller.SendAsync("Pong", new { 
                    timestamp = DateTime.UtcNow,
                    connectionId = Context.ConnectionId
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing ping for connection {ConnectionId}", Context.ConnectionId);
            }
        }

        /// <summary>
        /// Obtener estado de la conexión
        /// </summary>
        public async Task GetConnectionStatus()
        {
            try
            {
                var isActive = await _connectionService.IsConnectionActiveAsync(Context.ConnectionId);
                
                await Clients.Caller.SendAsync("ConnectionStatus", new { 
                    connectionId = Context.ConnectionId,
                    isActive,
                    timestamp = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting connection status for {ConnectionId}", Context.ConnectionId);
            }
        }

        /// <summary>
        /// Evento cuando un cliente se conecta
        /// </summary>
        public override async Task OnConnectedAsync()
        {
            var clientInfo = GetClientInfo();
            
            _logger.LogInformation("Client connected: {ConnectionId} from {ClientInfo}", 
                Context.ConnectionId, clientInfo);

            // Enviar mensaje de bienvenida
            await Clients.Caller.SendAsync("Connected", new { 
                connectionId = Context.ConnectionId,
                timestamp = DateTime.UtcNow,
                message = "WebSocket connection established",
                clientInfo
            });

            await base.OnConnectedAsync();
        }

        /// <summary>
        /// Evento cuando un cliente se desconecta
        /// </summary>
        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            try
            {
                // Desregistrar la conexión
                await _connectionService.UnregisterConnectionAsync(Context.ConnectionId);
                
                if (exception != null)
                {
                    _logger.LogWarning(exception, "Client disconnected with error: {ConnectionId}", Context.ConnectionId);
                }
                else
                {
                    _logger.LogInformation("Client disconnected: {ConnectionId}", Context.ConnectionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during disconnection cleanup for {ConnectionId}", Context.ConnectionId);
            }

            await base.OnDisconnectedAsync(exception);
        }

        /// <summary>
        /// Obtener información del cliente
        /// </summary>
        private string GetClientInfo()
        {
            var httpContext = Context.GetHttpContext();
            if (httpContext == null) return "Unknown";

            var userAgent = httpContext.Request.Headers.UserAgent.ToString();
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            
            return $"IP: {ipAddress}, UserAgent: {userAgent}";
        }
    }
}

