# Diseño de Arquitectura Híbrida: Webhooks + WebSockets

## 🎯 Objetivo
Implementar un sistema de notificaciones híbrido que permita a las aplicaciones frontend (especialmente React) recibir notificaciones de login de Office365 tanto por webhooks como por WebSockets en tiempo real.

## 🏗️ Arquitectura Propuesta

### 1. **Flujo Híbrido de Notificaciones**

```
Office365 Login → Backend → [Webhook + WebSocket] → Frontend React
```

**Ventajas:**
- **Webhooks**: Confiables, persistentes, con reintentos
- **WebSockets**: Tiempo real, bidireccionales, mejor UX
- **Híbrido**: Redundancia y flexibilidad según el caso de uso

### 2. **Casos de Uso por Tipo de Notificación**

| Escenario | Webhook | WebSocket | Ambos |
|-----------|---------|-----------|-------|
| Frontend conectado en tiempo real | ❌ | ✅ | ✅ |
| Frontend desconectado/cerrado | ✅ | ❌ | ✅ |
| Aplicaciones servidor-a-servidor | ✅ | ❌ | ❌ |
| Notificaciones críticas | ✅ | ❌ | ✅ |
| UX en tiempo real | ❌ | ✅ | ✅ |

## 📊 Cambios en Base de Datos

### 1. **Nueva Tabla: WebSocketConnections**
```sql
CREATE TABLE auth.tbl_WebSocketConnections (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    ApplicationId UNIQUEIDENTIFIER NOT NULL,
    ConnectionId NVARCHAR(100) NOT NULL UNIQUE,
    UserId UNIQUEIDENTIFIER NULL, -- NULL si es conexión anónima
    ClientInfo NVARCHAR(500) NULL, -- Browser, IP, etc.
    ConnectedAt DATETIME2(3) NOT NULL DEFAULT SYSDATETIME(),
    LastPingAt DATETIME2(3) NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (ApplicationId) REFERENCES auth.tbl_Applications(Id),
    FOREIGN KEY (UserId) REFERENCES auth.tbl_Users(Id),
    
    INDEX IX_WebSocketConnections_ApplicationId (ApplicationId),
    INDEX IX_WebSocketConnections_UserId (UserId),
    INDEX IX_WebSocketConnections_IsActive (IsActive)
);
```

### 2. **Modificar Tabla: NotificationSubscriptions**
```sql
-- Agregar columna para tipo de notificación
ALTER TABLE auth.tbl_NotificationSubscriptions 
ADD NotificationType NVARCHAR(20) NOT NULL DEFAULT 'webhook' 
    CHECK (NotificationType IN ('webhook', 'websocket', 'both'));

-- Hacer WebhookUrl opcional para conexiones WebSocket
ALTER TABLE auth.tbl_NotificationSubscriptions 
ALTER COLUMN WebhookUrl NVARCHAR(500) NULL;
```

### 3. **Nueva Tabla: WebSocketMessages**
```sql
CREATE TABLE auth.tbl_WebSocketMessages (
    Id BIGINT IDENTITY(1,1) PRIMARY KEY,
    ConnectionId NVARCHAR(100) NOT NULL,
    EventType NVARCHAR(50) NOT NULL,
    MessageData NVARCHAR(MAX) NOT NULL,
    SentAt DATETIME2(3) NOT NULL DEFAULT SYSDATETIME(),
    IsDelivered BIT NOT NULL DEFAULT 0,
    DeliveredAt DATETIME2(3) NULL,
    ErrorMessage NVARCHAR(500) NULL,
    
    INDEX IX_WebSocketMessages_ConnectionId (ConnectionId),
    INDEX IX_WebSocketMessages_EventType (EventType),
    INDEX IX_WebSocketMessages_SentAt (SentAt)
);
```

## 🔧 Cambios en Backend (.NET)

### 1. **Agregar Dependencias NuGet**
```xml
<PackageReference Include="Microsoft.AspNetCore.SignalR" Version="9.0.0" />
<PackageReference Include="Microsoft.AspNetCore.SignalR.Client" Version="9.0.0" />
```

### 2. **Nuevo Hub de SignalR**
```csharp
// Hubs/NotificationHub.cs
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;

namespace WsSeguUta.AuthSystem.API.Hubs
{
    [Authorize] // Opcional: requerir autenticación
    public class NotificationHub : Hub
    {
        private readonly IWebSocketConnectionService _connectionService;
        private readonly ILogger<NotificationHub> _logger;

        public NotificationHub(IWebSocketConnectionService connectionService, ILogger<NotificationHub> logger)
        {
            _connectionService = connectionService;
            _logger = logger;
        }

        public async Task JoinApplicationGroup(string clientId)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"app_{clientId}");
            await _connectionService.RegisterConnectionAsync(Context.ConnectionId, clientId, Context.User?.Identity?.Name);
            _logger.LogInformation("Client {ConnectionId} joined application group {ClientId}", Context.ConnectionId, clientId);
        }

        public async Task LeaveApplicationGroup(string clientId)
        {
            await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"app_{clientId}");
            _logger.LogInformation("Client {ConnectionId} left application group {ClientId}", Context.ConnectionId, clientId);
        }

        public override async Task OnConnectedAsync()
        {
            _logger.LogInformation("Client connected: {ConnectionId}", Context.ConnectionId);
            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            await _connectionService.UnregisterConnectionAsync(Context.ConnectionId);
            _logger.LogInformation("Client disconnected: {ConnectionId}", Context.ConnectionId);
            await base.OnDisconnectedAsync(exception);
        }
    }
}
```

### 3. **Nuevo Servicio: WebSocketConnectionService**
```csharp
// Services/Interfaces/IWebSocketConnectionService.cs
public interface IWebSocketConnectionService
{
    Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null);
    Task UnregisterConnectionAsync(string connectionId);
    Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId);
    Task<bool> IsConnectionActiveAsync(string connectionId);
    Task UpdateLastPingAsync(string connectionId);
}

// Services/Implementations/WebSocketConnectionService.cs
public class WebSocketConnectionService : IWebSocketConnectionService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<WebSocketConnectionService> _logger;

    public WebSocketConnectionService(AuthDbContext context, ILogger<WebSocketConnectionService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null)
    {
        var application = await _context.Applications
            .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive);

        if (application == null)
        {
            _logger.LogWarning("Application not found for clientId: {ClientId}", clientId);
            return;
        }

        Guid? userGuid = null;
        if (!string.IsNullOrEmpty(userId) && Guid.TryParse(userId, out var parsedUserId))
        {
            userGuid = parsedUserId;
        }

        var connection = new WebSocketConnection
        {
            ApplicationId = application.Id,
            ConnectionId = connectionId,
            UserId = userGuid,
            ConnectedAt = DateTime.UtcNow,
            LastPingAt = DateTime.UtcNow,
            IsActive = true
        };

        _context.WebSocketConnections.Add(connection);
        await _context.SaveChangesAsync();

        _logger.LogInformation("WebSocket connection registered: {ConnectionId} for app {ClientId}", connectionId, clientId);
    }

    public async Task UnregisterConnectionAsync(string connectionId)
    {
        var connection = await _context.WebSocketConnections
            .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

        if (connection != null)
        {
            connection.IsActive = false;
            await _context.SaveChangesAsync();
            _logger.LogInformation("WebSocket connection unregistered: {ConnectionId}", connectionId);
        }
    }

    public async Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId)
    {
        var connections = await _context.WebSocketConnections
            .Join(_context.Applications, wc => wc.ApplicationId, a => a.Id, (wc, a) => new { wc, a })
            .Where(x => x.a.ClientId == clientId && x.wc.IsActive)
            .Select(x => x.wc.ConnectionId)
            .ToListAsync();

        return connections;
    }

    public async Task<bool> IsConnectionActiveAsync(string connectionId)
    {
        return await _context.WebSocketConnections
            .AnyAsync(c => c.ConnectionId == connectionId && c.IsActive);
    }

    public async Task UpdateLastPingAsync(string connectionId)
    {
        var connection = await _context.WebSocketConnections
            .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

        if (connection != null)
        {
            connection.LastPingAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
        }
    }
}
```

### 4. **Modificar NotificationService para Soporte Híbrido**
```csharp
// Agregar al NotificationService existente
public class NotificationService : INotificationService
{
    private readonly IHubContext<NotificationHub> _hubContext;
    private readonly IWebSocketConnectionService _connectionService;
    
    // Constructor actualizado
    public NotificationService(
        AuthDbContext context, 
        IHttpClientFactory httpClientFactory, 
        ILogger<NotificationService> logger, 
        IConfiguration configuration,
        IHubContext<NotificationHub> hubContext,
        IWebSocketConnectionService connectionService)
    {
        // ... existing code ...
        _hubContext = hubContext;
        _connectionService = connectionService;
    }

    // Método híbrido para notificaciones
    public async Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId)
    {
        try
        {
            // 1. Buscar aplicación
            var application = await _context.Applications
                .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);
                
            if (application == null) return;

            // 2. Buscar suscripciones (webhooks Y websockets)
            var subscriptions = await _context.NotificationSubscriptions
                .Where(s => s.ApplicationId == application.Id && 
                           s.EventType == "Login" && 
                           s.IsActive)
                .ToListAsync();

            if (!subscriptions.Any()) return;

            // 3. Preparar datos del evento
            var user = await _context.Users.FindAsync(userId);
            if (user == null) return;

            var roles = await GetUserRoles(userId);
            var permissions = await GetUserPermissions(userId);

            var eventData = new
            {
                eventType = "Login",
                timestamp = DateTime.UtcNow,
                context = new
                {
                    initiatingApplication = clientId,
                    loginSource = loginType,
                    sessionScope = "specific",
                    notificationType = "hybrid"
                },
                data = new
                {
                    userId,
                    email = user.Email,
                    displayName = user.DisplayName,
                    loginType,
                    ipAddress,
                    roles,
                    permissions
                }
            };

            // 4. Enviar por cada tipo de suscripción
            foreach (var subscription in subscriptions)
            {
                switch (subscription.NotificationType?.ToLower())
                {
                    case "webhook":
                        await SendWebhookAsync(subscription, eventData);
                        break;
                        
                    case "websocket":
                        await SendWebSocketAsync(clientId, eventData);
                        break;
                        
                    case "both":
                    default:
                        await SendWebhookAsync(subscription, eventData);
                        await SendWebSocketAsync(clientId, eventData);
                        break;
                }
            }

            _logger.LogInformation("Hybrid notification sent for user {UserId} to application {ClientId}", userId, clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending hybrid notification to {ClientId}", clientId);
        }
    }

    // Nuevo método para envío por WebSocket
    private async Task SendWebSocketAsync(string clientId, object eventData)
    {
        try
        {
            // Enviar a todos los clientes conectados de esta aplicación
            await _hubContext.Clients.Group($"app_{clientId}")
                .SendAsync("LoginNotification", eventData);

            // Registrar mensaje en base de datos
            var connections = await _connectionService.GetActiveConnectionsForApplicationAsync(clientId);
            foreach (var connectionId in connections)
            {
                var message = new WebSocketMessage
                {
                    ConnectionId = connectionId,
                    EventType = "Login",
                    MessageData = System.Text.Json.JsonSerializer.Serialize(eventData),
                    SentAt = DateTime.UtcNow,
                    IsDelivered = true, // Asumimos entrega exitosa con SignalR
                    DeliveredAt = DateTime.UtcNow
                };

                _context.WebSocketMessages.Add(message);
            }

            await _context.SaveChangesAsync();
            _logger.LogInformation("WebSocket notification sent to application {ClientId}", clientId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending WebSocket notification to {ClientId}", clientId);
        }
    }
}
```

### 5. **Configuración en Program.cs**
```csharp
// Agregar después de las configuraciones existentes

// SignalR
builder.Services.AddSignalR(options =>
{
    options.EnableDetailedErrors = true;
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// WebSocket Services
builder.Services.AddScoped<IWebSocketConnectionService, WebSocketConnectionService>();

// En la configuración de la app
app.MapHub<NotificationHub>("/notificationHub");
```

## 📱 Implementación en Frontend React

### 1. **Instalación de Dependencias**
```bash
npm install @microsoft/signalr
```

### 2. **Hook de React para WebSocket**
```javascript
// hooks/useNotificationWebSocket.js
import { useEffect, useState, useCallback } from 'react';
import * as signalR from '@microsoft/signalr';

export const useNotificationWebSocket = (clientId, accessToken) => {
    const [connection, setConnection] = useState(null);
    const [isConnected, setIsConnected] = useState(false);
    const [notifications, setNotifications] = useState([]);

    const connectWebSocket = useCallback(async () => {
        try {
            const newConnection = new signalR.HubConnectionBuilder()
                .withUrl('/notificationHub', {
                    accessTokenFactory: () => accessToken
                })
                .withAutomaticReconnect()
                .build();

            // Configurar eventos
            newConnection.on('LoginNotification', (data) => {
                console.log('Login notification received:', data);
                setNotifications(prev => [...prev, data]);
                
                // Procesar notificación de login
                if (data.eventType === 'Login') {
                    localStorage.setItem('user', JSON.stringify(data.data));
                    window.location.href = '/dashboard';
                }
            });

            newConnection.onreconnected(() => {
                console.log('WebSocket reconnected');
                setIsConnected(true);
                // Re-unirse al grupo de la aplicación
                newConnection.invoke('JoinApplicationGroup', clientId);
            });

            newConnection.onclose(() => {
                console.log('WebSocket disconnected');
                setIsConnected(false);
            });

            // Conectar
            await newConnection.start();
            console.log('WebSocket connected');
            
            // Unirse al grupo de la aplicación
            await newConnection.invoke('JoinApplicationGroup', clientId);
            
            setConnection(newConnection);
            setIsConnected(true);

        } catch (error) {
            console.error('Error connecting to WebSocket:', error);
        }
    }, [clientId, accessToken]);

    const disconnectWebSocket = useCallback(async () => {
        if (connection) {
            await connection.stop();
            setConnection(null);
            setIsConnected(false);
        }
    }, [connection]);

    useEffect(() => {
        if (clientId && accessToken) {
            connectWebSocket();
        }

        return () => {
            disconnectWebSocket();
        };
    }, [clientId, accessToken, connectWebSocket, disconnectWebSocket]);

    return {
        isConnected,
        notifications,
        connection,
        reconnect: connectWebSocket,
        disconnect: disconnectWebSocket
    };
};
```

### 3. **Componente React de Login**
```javascript
// components/Office365Login.jsx
import React, { useEffect } from 'react';
import { useNotificationWebSocket } from '../hooks/useNotificationWebSocket';

const Office365Login = () => {
    const clientId = 'mi-app-frontend';
    const { isConnected, notifications } = useNotificationWebSocket(clientId, null);

    const handleOffice365Login = async () => {
        try {
            // 1. Obtener URL de Office365
            const response = await fetch(`/api/auth/azure/url?clientId=${clientId}`);
            const { url } = await response.json();
            
            // 2. Redirigir a Office365
            window.location.href = url;
            
        } catch (error) {
            console.error('Error initiating Office365 login:', error);
        }
    };

    useEffect(() => {
        // Procesar notificaciones recibidas
        notifications.forEach(notification => {
            if (notification.eventType === 'Login') {
                console.log('User logged in:', notification.data);
                // Actualizar estado de la aplicación
            }
        });
    }, [notifications]);

    return (
        <div>
            <div>
                WebSocket Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}
            </div>
            
            <button onClick={handleOffice365Login}>
                Login with Office365
            </button>
            
            {notifications.length > 0 && (
                <div>
                    <h3>Recent Notifications:</h3>
                    {notifications.map((notif, index) => (
                        <div key={index}>
                            {notif.eventType}: {notif.data.email}
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default Office365Login;
```

## 🔄 Flujo Completo Híbrido

### 1. **Inicialización**
```
Frontend React → Conecta WebSocket → Se une al grupo de aplicación
```

### 2. **Login Office365**
```
Frontend → GET /api/auth/azure/url?clientId=mi-app
Backend → Genera state con clientId
Office365 → Callback con code + state
Backend → Procesa login + Envía webhook + Envía WebSocket
Frontend → Recibe notificación en tiempo real
```

### 3. **Manejo de Desconexiones**
```
Si WebSocket desconectado → Solo webhook (fallback)
Si WebSocket conectado → Ambos (redundancia)
```

## 📊 Ventajas de la Arquitectura Híbrida

1. **Tiempo Real**: WebSockets para UX inmediata
2. **Confiabilidad**: Webhooks como respaldo
3. **Flexibilidad**: Aplicaciones pueden elegir el tipo
4. **Escalabilidad**: SignalR maneja múltiples conexiones
5. **Monitoreo**: Logs completos de ambos canales
6. **Compatibilidad**: Funciona con aplicaciones existentes

Esta arquitectura te permite tener lo mejor de ambos mundos: la inmediatez de WebSockets para una mejor experiencia de usuario y la confiabilidad de webhooks para garantizar que las notificaciones lleguen incluso si el frontend está desconectado.

