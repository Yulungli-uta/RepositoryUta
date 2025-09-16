# Optimización: Reutilizar Tablas Existentes para WebSockets

## 🎯 Objetivo
Reutilizar al máximo las tablas existentes de `NotificationSubscription` y `NotificationLog` agregando solo el campo `NotificationType` para soportar tanto webhooks como WebSockets.

## 📊 Cambios Mínimos en Base de Datos

### 1. **Modificar Tabla Existente: NotificationSubscription**
```sql
-- Solo agregar una columna para el tipo
ALTER TABLE auth.tbl_NotificationSubscriptions 
ADD NotificationType NVARCHAR(20) NOT NULL DEFAULT 'webhook' 
    CONSTRAINT CK_NotificationSubscriptions_NotificationType 
    CHECK (NotificationType IN ('webhook', 'websocket', 'both'));

-- Hacer WebhookUrl opcional para WebSockets
ALTER TABLE auth.tbl_NotificationSubscriptions 
ALTER COLUMN WebhookUrl NVARCHAR(500) NULL;
```

### 2. **Reutilizar NotificationLog para WebSockets**
```sql
-- No necesita cambios, ya sirve para ambos tipos
-- Solo agregar índice para mejor performance
CREATE INDEX IX_NotificationLog_EventType_IsSuccess 
ON auth.tbl_NotificationLogs (EventType, IsSuccess);
```

### 3. **Solo Agregar Tabla Mínima para Conexiones**
```sql
-- Tabla simple solo para tracking de conexiones activas
CREATE TABLE auth.tbl_WebSocketConnections (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    ApplicationId UNIQUEIDENTIFIER NOT NULL,
    ConnectionId NVARCHAR(100) NOT NULL UNIQUE,
    UserId UNIQUEIDENTIFIER NULL,
    ConnectedAt DATETIME2(3) NOT NULL DEFAULT SYSDATETIME(),
    LastPingAt DATETIME2(3) NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (ApplicationId) REFERENCES auth.tbl_Applications(Id),
    INDEX IX_WebSocketConnections_ApplicationId_Active (ApplicationId, IsActive)
);
```

## 🔧 Implementación Optimizada

### 1. **Entidad NotificationSubscription Actualizada**
```csharp
public class NotificationSubscription 
{ 
    public Guid Id { get; set; } = Guid.NewGuid(); 
    public Guid ApplicationId { get; set; } 
    public string EventType { get; set; } = string.Empty; // "Login", "Logout", etc.
    public string? WebhookUrl { get; set; } // NULL para WebSockets puros
    public string? SecretKey { get; set; } 
    public string NotificationType { get; set; } = "webhook"; // "webhook", "websocket", "both"
    public bool IsActive { get; set; } = true; 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
    public string? CreatedBy { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public string? ModifiedBy { get; set; }
}
```

### 2. **Reutilizar NotificationLog para Ambos Tipos**
```csharp
// La entidad existente ya sirve para ambos
public class NotificationLog 
{ 
    public long Id { get; set; } 
    public Guid SubscriptionId { get; set; } 
    public string EventType { get; set; } = string.Empty; 
    public Guid? UserId { get; set; } 
    public string WebhookUrl { get; set; } = string.Empty; // Para WebSocket será "websocket://connectionId"
    public int? HttpStatusCode { get; set; } // Para WebSocket será 200 si exitoso
    public string? ResponseBody { get; set; } // Para WebSocket será "delivered" o error
    public int? ResponseTime { get; set; } 
    public bool IsSuccess { get; set; } = false; 
    public string? ErrorMessage { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
}
```

### 3. **NotificationService Híbrido Optimizado**
```csharp
public async Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId)
{
    try
    {
        // 1. Buscar aplicación
        var application = await _context.Applications
            .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);
            
        if (application == null) return;

        // 2. Buscar TODAS las suscripciones de login para esta app
        var subscriptions = await _context.NotificationSubscriptions
            .Where(s => s.ApplicationId == application.Id && 
                       s.EventType == "Login" && 
                       s.IsActive)
            .ToListAsync();

        if (!subscriptions.Any()) return;

        // 3. Preparar datos del evento UNA SOLA VEZ
        var eventData = await PrepareLoginEventData(userId, loginType, ipAddress, clientId);

        // 4. Procesar cada suscripción según su tipo
        foreach (var subscription in subscriptions)
        {
            switch (subscription.NotificationType?.ToLower())
            {
                case "webhook":
                    await SendWebhookNotification(subscription, eventData);
                    break;
                    
                case "websocket":
                    await SendWebSocketNotification(subscription, eventData, clientId);
                    break;
                    
                case "both":
                    // Enviar por ambos canales
                    await SendWebhookNotification(subscription, eventData);
                    await SendWebSocketNotification(subscription, eventData, clientId);
                    break;
            }
        }

        _logger.LogInformation("Hybrid notifications sent for user {UserId} to application {ClientId}", userId, clientId);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Error sending hybrid notifications to {ClientId}", clientId);
    }
}

// Método reutilizable para preparar datos
private async Task<object> PrepareLoginEventData(Guid userId, string loginType, string? ipAddress, string clientId)
{
    var user = await _context.Users.FindAsync(userId);
    if (user == null) return null;

    var roles = await GetUserRoles(userId);
    var permissions = await GetUserPermissions(userId);

    return new
    {
        eventType = "Login",
        timestamp = DateTime.UtcNow,
        context = new
        {
            initiatingApplication = clientId,
            loginSource = loginType,
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
}

// Webhook usando método existente
private async Task SendWebhookNotification(NotificationSubscription subscription, object eventData)
{
    if (string.IsNullOrEmpty(subscription.WebhookUrl)) return;
    
    // Reutilizar método existente
    await SendWebhookAsync(subscription, eventData);
}

// WebSocket usando la misma estructura de log
private async Task SendWebSocketNotification(NotificationSubscription subscription, object eventData, string clientId)
{
    var startTime = DateTime.UtcNow;
    
    try
    {
        // Enviar por SignalR
        await _hubContext.Clients.Group($"app_{clientId}")
            .SendAsync("LoginNotification", eventData);

        // Registrar en el MISMO log que webhooks
        var log = new NotificationLog
        {
            SubscriptionId = subscription.Id,
            EventType = "Login",
            WebhookUrl = $"websocket://app_{clientId}", // Identificador especial
            HttpStatusCode = 200, // Exitoso
            ResponseBody = "delivered",
            IsSuccess = true,
            ResponseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds,
            CreatedAt = DateTime.UtcNow
        };

        _context.NotificationLogs.Add(log);
        await _context.SaveChangesAsync();

        _logger.LogInformation("WebSocket notification sent to application {ClientId}", clientId);
    }
    catch (Exception ex)
    {
        // Registrar error en el MISMO log
        var errorLog = new NotificationLog
        {
            SubscriptionId = subscription.Id,
            EventType = "Login",
            WebhookUrl = $"websocket://app_{clientId}",
            HttpStatusCode = 0,
            IsSuccess = false,
            ResponseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds,
            ErrorMessage = ex.Message,
            CreatedAt = DateTime.UtcNow
        };

        _context.NotificationLogs.Add(errorLog);
        await _context.SaveChangesAsync();

        _logger.LogError(ex, "Error sending WebSocket notification to {ClientId}", clientId);
    }
}
```

## 📝 Crear Suscripciones Híbridas

### 1. **Webhook Tradicional**
```bash
POST /api/notifications/subscriptions
{
  "applicationId": "guid-de-la-aplicacion",
  "eventType": "Login",
  "webhookUrl": "https://mi-frontend.com/api/auth/webhook",
  "secretKey": "clave-secreta",
  "notificationType": "webhook"
}
```

### 2. **WebSocket Puro**
```bash
POST /api/notifications/subscriptions
{
  "applicationId": "guid-de-la-aplicacion",
  "eventType": "Login",
  "webhookUrl": null,
  "secretKey": null,
  "notificationType": "websocket"
}
```

### 3. **Híbrido (Ambos)**
```bash
POST /api/notifications/subscriptions
{
  "applicationId": "guid-de-la-aplicacion",
  "eventType": "Login",
  "webhookUrl": "https://mi-frontend.com/api/auth/webhook",
  "secretKey": "clave-secreta",
  "notificationType": "both"
}
```

## 📊 Consultas Unificadas

### 1. **Estadísticas por Tipo de Notificación**
```sql
SELECT 
    ns.NotificationType,
    COUNT(*) as TotalSubscriptions,
    SUM(CASE WHEN ns.IsActive = 1 THEN 1 ELSE 0 END) as ActiveSubscriptions
FROM auth.tbl_NotificationSubscriptions ns
GROUP BY ns.NotificationType;
```

### 2. **Logs Unificados (Webhook + WebSocket)**
```sql
SELECT 
    nl.EventType,
    CASE 
        WHEN nl.WebhookUrl LIKE 'websocket://%' THEN 'WebSocket'
        ELSE 'Webhook'
    END as NotificationMethod,
    COUNT(*) as TotalNotifications,
    SUM(CASE WHEN nl.IsSuccess = 1 THEN 1 ELSE 0 END) as SuccessfulNotifications,
    AVG(nl.ResponseTime) as AvgResponseTime
FROM auth.tbl_NotificationLogs nl
WHERE nl.CreatedAt >= DATEADD(DAY, -7, GETDATE())
GROUP BY nl.EventType, 
         CASE WHEN nl.WebhookUrl LIKE 'websocket://%' THEN 'WebSocket' ELSE 'Webhook' END
ORDER BY nl.EventType, NotificationMethod;
```

### 3. **Vista Unificada de Rendimiento**
```sql
CREATE VIEW auth.vw_NotificationPerformance AS
SELECT 
    a.Name as ApplicationName,
    a.ClientId,
    ns.EventType,
    ns.NotificationType,
    COUNT(nl.Id) as TotalNotifications,
    SUM(CASE WHEN nl.IsSuccess = 1 THEN 1 ELSE 0 END) as SuccessfulNotifications,
    AVG(nl.ResponseTime) as AvgResponseTimeMs,
    MAX(nl.CreatedAt) as LastNotification
FROM auth.tbl_Applications a
INNER JOIN auth.tbl_NotificationSubscriptions ns ON a.Id = ns.ApplicationId
LEFT JOIN auth.tbl_NotificationLogs nl ON ns.Id = nl.SubscriptionId
WHERE a.IsActive = 1 AND a.IsDeleted = 0
GROUP BY a.Id, a.Name, a.ClientId, ns.EventType, ns.NotificationType;
```

## 🎯 Ventajas de Esta Optimización

### 1. **Reutilización Máxima**
- ✅ Misma tabla `NotificationSubscription` para ambos tipos
- ✅ Mismo `NotificationLog` para tracking unificado
- ✅ Misma API para crear suscripciones
- ✅ Mismas consultas de estadísticas

### 2. **Migración Mínima**
- ✅ Solo agregar 1 columna a tabla existente
- ✅ Solo 1 tabla nueva para conexiones WebSocket
- ✅ Código existente sigue funcionando
- ✅ Backward compatibility completa

### 3. **Administración Simplificada**
- ✅ Un solo endpoint para gestionar suscripciones
- ✅ Logs unificados en una sola tabla
- ✅ Estadísticas consolidadas
- ✅ Monitoreo centralizado

### 4. **Flexibilidad Total**
- ✅ Aplicaciones pueden elegir webhook, websocket o ambos
- ✅ Cambiar tipo sin recrear suscripción
- ✅ Migración gradual de webhook a websocket
- ✅ Redundancia automática con tipo "both"

## 🚀 Script de Migración Optimizado

```sql
-- Migración mínima para soporte híbrido
USE [WsSeguUta_AuthSystem];
GO

-- 1. Agregar columna de tipo
ALTER TABLE auth.tbl_NotificationSubscriptions 
ADD NotificationType NVARCHAR(20) NOT NULL DEFAULT 'webhook' 
    CONSTRAINT CK_NotificationSubscriptions_NotificationType 
    CHECK (NotificationType IN ('webhook', 'websocket', 'both'));

-- 2. Hacer WebhookUrl opcional
ALTER TABLE auth.tbl_NotificationSubscriptions 
ALTER COLUMN WebhookUrl NVARCHAR(500) NULL;

-- 3. Tabla mínima para conexiones
CREATE TABLE auth.tbl_WebSocketConnections (
    Id UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    ApplicationId UNIQUEIDENTIFIER NOT NULL,
    ConnectionId NVARCHAR(100) NOT NULL UNIQUE,
    UserId UNIQUEIDENTIFIER NULL,
    ConnectedAt DATETIME2(3) NOT NULL DEFAULT SYSDATETIME(),
    LastPingAt DATETIME2(3) NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (ApplicationId) REFERENCES auth.tbl_Applications(Id),
    INDEX IX_WebSocketConnections_ApplicationId_Active (ApplicationId, IsActive)
);

-- 4. Índice para mejor performance
CREATE INDEX IX_NotificationLog_EventType_IsSuccess 
ON auth.tbl_NotificationLogs (EventType, IsSuccess);

PRINT 'Migración híbrida completada con cambios mínimos';
```

Esta optimización te permite tener lo mejor de ambos mundos con cambios mínimos en tu estructura existente. ¿Te parece bien esta aproximación más simple?

