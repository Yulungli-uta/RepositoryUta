# Sistema de Notificaciones para Login con Office365

## 🎯 Solución Implementada

He implementado un **sistema completo de notificaciones** que resuelve tu inquietud sobre cómo notificar a cada sistema cuando alguien se loguea con Office365.

## 🔧 Cómo Funciona

### 1. **Registro de Webhooks**
Los sistemas legacy pueden registrar webhooks para recibir notificaciones automáticas:

```http
POST /api/notifications/subscriptions
Content-Type: application/json
Authorization: Bearer {token}

{
  "applicationId": "10000000-0000-0000-0000-000000000001",
  "eventType": "Login",
  "webhookUrl": "https://tu-sistema.com/webhooks/login",
  "secretKey": "tu-clave-secreta-para-validar"
}
```

### 2. **Eventos Automáticos**
Cuando alguien se loguea con Office365, el sistema automáticamente:

1. ✅ **Detecta el login** en `AzureAuthService.HandleCallbackAsync()`
2. ✅ **Crea un evento** de notificación
3. ✅ **Busca suscripciones** activas para el evento "Login"
4. ✅ **Envía webhooks** a todos los sistemas suscritos
5. ✅ **Registra logs** detallados del envío

### 3. **Payload del Webhook**
Los sistemas legacy reciben un payload como este:

```json
{
  "eventType": "Login",
  "timestamp": "2024-09-10T15:30:00Z",
  "data": {
    "userId": "22222222-2222-2222-2222-222222222222",
    "email": "usuario@empresa.com",
    "displayName": "María Gómez",
    "loginType": "Office365",
    "ipAddress": "192.168.1.100",
    "loginTime": "2024-09-10T15:30:00Z",
    "roles": ["Usuario", "Supervisor"],
    "permissions": [
      {
        "id": 1,
        "name": "Users_Read",
        "module": "Users",
        "action": "Read"
      }
    ]
  },
  "signature": "a1b2c3d4e5f6..." // Para validar autenticidad
}
```

## 📡 Endpoints Disponibles

### Gestión de Suscripciones

```http
# Crear suscripción
POST /api/notifications/subscriptions

# Actualizar suscripción
PUT /api/notifications/subscriptions/{id}

# Eliminar suscripción
DELETE /api/notifications/subscriptions/{id}

# Ver suscripciones de una aplicación
GET /api/notifications/subscriptions/application/{applicationId}

# Ver estadísticas
GET /api/notifications/stats
GET /api/notifications/stats/application/{applicationId}

# Procesar notificaciones pendientes (manual)
POST /api/notifications/process-pending

# Endpoint de prueba para webhooks
POST /api/notifications/webhook-test
```

## 🔐 Tipos de Eventos Soportados

- **`Login`** - Cuando un usuario se autentica (Office365, local, etc.)
- **`Logout`** - Cuando un usuario cierra sesión
- **`UserCreated`** - Cuando se crea un nuevo usuario
- **`UserUpdated`** - Cuando se actualiza un usuario
- **`RoleChanged`** - Cuando cambian los roles de un usuario

## 🛡️ Seguridad

### Validación de Webhooks
Cada webhook incluye una firma HMAC-SHA256:

```csharp
// En tu sistema legacy, valida así:
public bool ValidateWebhook(string payload, string signature, string secretKey)
{
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
    var expectedSignature = Convert.ToHexString(hash).ToLower();
    return signature == expectedSignature;
}
```

### Headers de Seguridad
```http
X-Webhook-Signature: a1b2c3d4e5f6...
Content-Type: application/json
```

## 🔄 Reintentos y Confiabilidad

- **Reintentos automáticos:** Hasta 3 intentos en caso de fallo
- **Logs detallados:** Cada envío se registra con código de respuesta y tiempo
- **Monitoreo:** Estadísticas de éxito/fallo por aplicación
- **Procesamiento asíncrono:** No bloquea el login del usuario

## 📊 Monitoreo y Estadísticas

### Estadísticas Generales
```json
{
  "totalSubscriptions": 15,
  "activeSubscriptions": 12,
  "totalEvents": 1250,
  "pendingEvents": 3,
  "failedNotifications": 8
}
```

### Estadísticas por Aplicación
```json
[
  {
    "subscriptionId": "guid",
    "eventType": "Login",
    "webhookUrl": "https://erp.empresa.com/webhooks/login",
    "isActive": true,
    "totalNotifications": 450,
    "successfulNotifications": 445,
    "failedNotifications": 5,
    "lastNotified": "2024-09-10T15:30:00Z"
  }
]
```

## 🚀 Configuración Rápida

### 1. Ejecutar Script SQL
```sql
-- Ejecutar: Database/centralizador_auth_changes.sql
-- Esto crea todas las tablas necesarias
```

### 2. Registrar tu Sistema
```http
POST /api/notifications/subscriptions
{
  "applicationId": "tu-app-id",
  "eventType": "Login",
  "webhookUrl": "https://tu-sistema.com/webhook",
  "secretKey": "tu-clave-secreta"
}
```

### 3. Implementar Endpoint en tu Sistema
```csharp
[HttpPost("webhook")]
public async Task<IActionResult> ReceiveNotification([FromBody] WebhookPayload payload)
{
    // Validar firma
    var signature = Request.Headers["X-Webhook-Signature"];
    if (!ValidateWebhook(payload, signature, "tu-clave-secreta"))
        return Unauthorized();
    
    // Procesar evento
    if (payload.EventType == "Login")
    {
        var loginData = (LoginEventData)payload.Data;
        await ProcessUserLogin(loginData);
    }
    
    return Ok(new { status = "received" });
}
```

## 🧪 Pruebas

### Endpoint de Prueba
```http
POST /api/notifications/webhook-test
{
  "test": "data",
  "timestamp": "2024-09-10T15:30:00Z"
}
```

### Respuesta de Prueba
```json
{
  "status": "Success",
  "message": "Webhook received successfully",
  "timestamp": "2024-09-10T15:30:00Z",
  "receivedPayload": { ... }
}
```

## 📋 Ejemplos de Uso

### Sistema ERP
```javascript
// Recibir notificación de login
app.post('/webhooks/auth/login', (req, res) => {
  const { data } = req.body;
  
  // Actualizar sesión del usuario en ERP
  updateUserSession(data.userId, data.roles);
  
  // Registrar en log de auditoría
  auditLog.record('user_login', data);
  
  res.json({ status: 'processed' });
});
```

### Portal de Empleados
```python
@app.route('/api/notifications/login', methods=['POST'])
def handle_login_notification():
    payload = request.json
    user_data = payload['data']
    
    # Actualizar caché de permisos
    cache.set(f"user_permissions_{user_data['userId']}", 
              user_data['permissions'], timeout=3600)
    
    # Enviar notificación push
    send_push_notification(user_data['userId'], 
                          f"Login desde {user_data['loginType']}")
    
    return {'status': 'ok'}
```

## ❗ Importante

### Aclaración sobre "AddCentralizadorEntities"
**"AddCentralizadorEntities" NO existe** - es el nombre que TÚ debes dar a la migración:

```bash
# Opción 1: Usar Entity Framework
dotnet ef migrations add AgregarSistemaNotificaciones
dotnet ef database update

# Opción 2: Ejecutar SQL directamente
# Ejecutar el archivo: Database/centralizador_auth_changes.sql
```

## 🎉 Resultado Final

Con esta implementación, **cada vez que alguien se loguee con Office365**:

1. 🔔 **Todos los sistemas suscritos** reciben una notificación inmediata
2. 📊 **Datos completos** del usuario, roles y permisos incluidos
3. 🔒 **Seguridad garantizada** con firmas HMAC
4. 📝 **Logs detallados** para auditoría y troubleshooting
5. 🔄 **Reintentos automáticos** en caso de fallos temporales

¡Tu problema está completamente resuelto! 🚀

