using Microsoft.AspNetCore.SignalR;
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
                Console.WriteLine(
                    $"[NotificationHub] JoinApplicationGroup → conn: {Context.ConnectionId}, clientId: {clientId}, userId: {userId ?? "anonymous"}");

                // Unirse al grupo de la aplicación
                await Groups.AddToGroupAsync(Context.ConnectionId, $"app_{clientId}");

                // Registrar/actualizar la conexión en la base de datos
                await _connectionService.RegisterConnectionAsync(Context.ConnectionId, clientId, userId);

                _logger.LogInformation(
                    "Client {ConnectionId} joined application group {ClientId} with user {UserId}",
                    Context.ConnectionId, clientId, userId ?? "anonymous");

                // Confirmar al cliente que se unió exitosamente
                await Clients.Caller.SendAsync("JoinedGroup", new
                {
                    clientId,
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.Now,
                    message = $"Successfully joined notifications for {clientId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error joining application group {ClientId} for connection {ConnectionId}",
                    clientId, Context.ConnectionId);

                await Clients.Caller.SendAsync("Error", new
                {
                    message = "Failed to join application group",
                    error = ex.Message
                });
            }
        }

        /// <summary>
        /// 🔑 Unirse al grupo específico de un navegador (browserId)
        /// Esto permite que el backend envíe notificaciones SOLO a ese navegador.
        /// </summary>
        /// <param name="clientId">ID de la aplicación cliente</param>
        /// <param name="browserId">Identificador único del navegador</param>
        public async Task JoinBrowserGroup(string clientId, string browserId)
        {
            try
            {
                Console.WriteLine(
                    $"[NotificationHub] JoinBrowserGroup → conn: {Context.ConnectionId}, clientId: {clientId}, browserId: {browserId}");

                // Unirse al grupo específico del navegador
                await Groups.AddToGroupAsync(Context.ConnectionId, $"browser_{browserId}");

                // Registrar conexión con BrowserId, IP y UserAgent
                await _connectionService.RegisterConnectionAsync(Context.ConnectionId, clientId, null, browserId);

                _logger.LogInformation(
                    "Client {ConnectionId} joined browser group {BrowserGroup} for app {ClientId}",
                    Context.ConnectionId, $"browser_{browserId}", clientId);

                await Clients.Caller.SendAsync("JoinedBrowserGroup", new
                {
                    clientId,
                    browserId,
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.Now,
                    message = $"Successfully joined browser group for {browserId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error joining browser group {BrowserId} for connection {ConnectionId}",
                    browserId, Context.ConnectionId);

                await Clients.Caller.SendAsync("Error", new
                {
                    message = "Failed to join browser group",
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

                _logger.LogInformation(
                    "Client {ConnectionId} left application group {ClientId}",
                    Context.ConnectionId, clientId);

                await Clients.Caller.SendAsync("LeftGroup", new
                {
                    clientId,
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.Now,
                    message = $"Successfully left notifications for {clientId}"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error leaving application group {ClientId} for connection {ConnectionId}",
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
                await Clients.Caller.SendAsync("Pong", new
                {
                    timestamp = DateTime.Now,
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

                await Clients.Caller.SendAsync("ConnectionStatus", new
                {
                    connectionId = Context.ConnectionId,
                    isActive,
                    timestamp = DateTime.Now
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting connection status for {ConnectionId}", Context.ConnectionId);
            }
        }

        /// <summary>
        /// Evento cuando un cliente se conecta
        /// Aquí también aprovechamos para unirlo automáticamente
        /// a los grupos app_{clientId} y browser_{browserId} si vienen en la query.
        /// </summary>
        public override async Task OnConnectedAsync()
        {
            var httpContext = Context.GetHttpContext();
            var clientId = httpContext?.Request.Query["clientId"].ToString();
            var browserId = httpContext?.Request.Query["browserId"].ToString();
            var userId = httpContext?.Request.Query["userId"].ToString();

            var clientInfo = GetClientInfo();

            _logger.LogInformation(
                "Client connected: {ConnectionId} from {ClientInfo} (clientId={ClientId}, browserId={BrowserId})",
                Context.ConnectionId, clientInfo, clientId, browserId);

            try
            {
                // Grupo por aplicación
                if (!string.IsNullOrEmpty(clientId))
                {
                    await Groups.AddToGroupAsync(Context.ConnectionId, $"app_{clientId}");
                }

                // Grupo específico por navegador
                if (!string.IsNullOrEmpty(browserId))
                {
                    await Groups.AddToGroupAsync(Context.ConnectionId, $"browser_{browserId}");
                }

                // Registrar la conexión en BD (si tenemos clientId)
                if (!string.IsNullOrEmpty(clientId))
                {
                    await _connectionService.RegisterConnectionAsync(
                        Context.ConnectionId,
                        clientId,
                        userId
                    );
                }

                // Enviar mensaje de bienvenida
                await Clients.Caller.SendAsync("Connected", new
                {
                    connectionId = Context.ConnectionId,
                    timestamp = DateTime.Now,
                    message = "WebSocket connection established",
                    clientInfo,
                    clientId,
                    browserId
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error during OnConnectedAsync for {ConnectionId}", Context.ConnectionId);
            }

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
                    _logger.LogWarning(exception,
                        "Client disconnected with error: {ConnectionId}", Context.ConnectionId);
                }
                else
                {
                    _logger.LogInformation("Client disconnected: {ConnectionId}", Context.ConnectionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Error during disconnection cleanup for {ConnectionId}", Context.ConnectionId);
            }

            await base.OnDisconnectedAsync(exception);
        }

        /// <summary>
        /// Obtener información del cliente (IP y UserAgent)
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
