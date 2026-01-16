# Flujo de Notificaciones después del Login de Office365

## 📋 Resumen del Flujo

Cuando un usuario se loguea con Office365, el sistema identifica qué aplicación frontend inició el proceso y le envía una notificación webhook específica con los datos del usuario autenticado.

## 🔄 Flujo Paso a Paso

### 1. **Inicio del Login (Frontend → Backend)**
```javascript
// El frontend solicita la URL de Office365
const response = await fetch('/api/auth/azure/url?clientId=mi-app-frontend');
const { url, state, clientId } = await response.json();

// Redirige al usuario a Office365
window.location.href = url;
```

### 2. **Generación del State (Backend)**
**Archivo:** `Services/Implementations/_All.cs` - Método `BuildAuthUrlAsync`

```csharp
public async Task<(string Url,string State)> BuildAuthUrlAsync(string? clientId = null)
{
  var stateGuid = Guid.NewGuid().ToString("N");
  
  // ✅ Crear state con información de la aplicación
  var stateData = new
  {
    stateId = stateGuid,
    clientId = clientId,  // ← AQUÍ se guarda qué app inició el login
    timestamp = DateTime.Now.ToString("O"),
    source = "azure_auth"
  };
  
  var stateJson = System.Text.Json.JsonSerializer.Serialize(stateData);
  var stateEncoded = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(stateJson));
  
  // ✅ Guardar en cache para validación
  _cache.Set($"ms_state:{stateGuid}", stateData, TimeSpan.FromMinutes(10));
  
  // Enviar a Office365 con el state codificado
  var url = await cca.GetAuthorizationRequestUrl(scopes)
    .WithExtraQueryParameters(new Dictionary<string, string> { { "state", stateEncoded } })
    .ExecuteAsync();
  
  return (url.ToString(), stateEncoded);
}
```

### 3. **Callback de Office365 (Office365 → Backend)**
**Archivo:** `Controllers/AuthController.cs` - Método `AzureCallback`

```csharp
[HttpGet("azure/callback")]
public async Task<IActionResult> AzureCallback([FromQuery] string code,[FromQuery] string state)
{
  // Obtener IP del cliente
  var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
  
  string? clientId = null;
  
  try
  {
    // ✅ DECODIFICAR STATE para recuperar qué app inició el login
    var stateJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(state));
    var stateData = System.Text.Json.JsonSerializer.Deserialize<JsonElement>(stateJson);
    
    clientId = stateData.TryGetProperty("clientId", out var clientIdProp) 
      ? clientIdProp.GetString() 
      : null;
    
    Console.WriteLine($"Login iniciado por aplicación: {clientId}");
  }
  catch (Exception ex)
  {
    Console.WriteLine($"Error decodificando state: {ex.Message}");
  }
  
  // Procesar el login con Office365
  var pair = await _azure.HandleCallbackAsync(code, state);
  
  if (pair != null)
  {
    // ========== AQUÍ SE ENVÍAN LAS NOTIFICACIONES ==========
    if (!string.IsNullOrEmpty(clientId))
    {
      // ✅ Notificar SOLO a la aplicación específica
      await _notificationService.NotifyLoginEventForApplicationAsync(
        userId, "Office365", clientIp, clientId
      );
    }
    else
    {
      // ✅ Notificar a todas las aplicaciones (fallback)
      await _notificationService.NotifyLoginEventAsync(
        userId, "Office365", clientIp, null, null
      );
    }
  }
  
  return Ok(ApiResponse.Ok(pair));
}
```

### 4. **Búsqueda de URLs de Webhook (Backend)**
**Archivo:** `Services/Implementations/_All.cs` - Método `NotifyLoginEventForApplicationAsync`

```csharp
public async Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId)
{
  try
  {
    // ✅ 1. Buscar la aplicación específica por ClientId
    var application = await _context.Applications
      .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);
      
    if (application == null)
    {
      Console.WriteLine($"Aplicación {clientId} no encontrada");
      return;
    }
    
    // ✅ 2. Buscar suscripciones de webhook SOLO de esta aplicación
    var subscriptions = await _context.NotificationSubscriptions
      .Where(s => s.ApplicationId == application.Id && 
                  s.EventType == "Login" && 
                  s.IsActive)
      .ToListAsync();
    
    if (!subscriptions.Any())
    {
      Console.WriteLine($"No hay suscripciones de login para {clientId}");
      return;
    }
    
    // ✅ 3. Obtener datos del usuario
    var user = await _context.Users.FindAsync(userId);
    var roles = await GetUserRoles(userId);
    var permissions = await GetUserPermissions(userId);
    
    // ✅ 4. Crear payload del evento
    var eventData = new
    {
      eventType = "Login",
      timestamp = DateTime.Now,
      context = new
      {
        initiatingApplication = clientId,
        loginSource = loginType,
        sessionScope = "specific",
        notificationType = "targeted"
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
    
    // ✅ 5. Enviar webhook a cada URL registrada
    foreach (var subscription in subscriptions)
    {
      await SendWebhookAsync(subscription, eventData);
      Console.WriteLine($"Notificación enviada a {clientId} en {subscription.WebhookUrl}");
    }
  }
  catch (Exception ex)
  {
    Console.WriteLine($"Error enviando notificación a {clientId}: {ex.Message}");
  }
}
```

### 5. **Envío del Webhook HTTP (Backend → Frontend)**
**Archivo:** `Services/Implementations/_All.cs` - Método `SendWebhookAsync`

```csharp
private async Task SendWebhookAsync(NotificationSubscription subscription, object eventData)
{
  var httpClient = _httpClientFactory.CreateClient();
  
  try
  {
    // ✅ Serializar datos del evento
    var jsonPayload = System.Text.Json.JsonSerializer.Serialize(eventData);
    var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

    // ✅ Configurar seguridad con firma HMAC
    httpClient.Timeout = TimeSpan.FromSeconds(30);
    if (!string.IsNullOrEmpty(subscription.SecretKey))
    {
      var signature = GenerateSignature(jsonPayload, subscription.SecretKey);
      content.Headers.Add("X-Webhook-Signature", signature);
    }

    // ✅ ENVIAR POST HTTP a la URL del webhook
    var response = await httpClient.PostAsync(subscription.WebhookUrl, content);
    var responseBody = await response.Content.ReadAsStringAsync();
    
    // ✅ Registrar log del envío
    var log = new NotificationLog
    {
      SubscriptionId = subscription.Id,
      WebhookUrl = subscription.WebhookUrl,
      HttpStatusCode = (int)response.StatusCode,
      ResponseBody = responseBody,
      IsSuccess = response.IsSuccessStatusCode,
      ResponseTime = responseTime
    };

    _context.NotificationLogs.Add(log);
    await _context.SaveChangesAsync();
  }
  catch (Exception ex)
  {
    // Log de error...
  }
}
```

## 🔧 Configuración de URLs de Webhook

### ¿De dónde salen las URLs?

Las URLs de webhook se registran previamente en la base de datos usando la API:

**1. Registrar una aplicación:**
```bash
POST /api/app-auth/applications
{
  "name": "Mi Frontend App",
  "clientId": "mi-app-frontend",
  "clientSecret": "mi-secreto-seguro",
  "description": "Aplicación frontend principal"
}
```

**2. Registrar webhook para notificaciones:**
```bash
POST /api/notifications/subscriptions
{
  "applicationId": "guid-de-la-aplicacion",
  "eventType": "Login",
  "webhookUrl": "https://mi-frontend.com/api/auth/webhook",
  "secretKey": "clave-secreta-para-hmac"
}
```

### Estructura de la Base de Datos

**Tabla: `NotificationSubscriptions`**
```sql
CREATE TABLE auth.tbl_NotificationSubscriptions (
    Id UNIQUEIDENTIFIER PRIMARY KEY,
    ApplicationId UNIQUEIDENTIFIER,  -- ← Vincula con la aplicación
    EventType NVARCHAR(50),          -- ← "Login", "Logout", etc.
    WebhookUrl NVARCHAR(500),        -- ← URL donde enviar la notificación
    SecretKey NVARCHAR(255),         -- ← Para firma HMAC
    IsActive BIT DEFAULT 1
);
```

## 📨 Payload que Recibe el Frontend

Cuando el usuario se loguea con Office365, tu frontend recibe este POST HTTP:

```json
{
  "eventType": "Login",
  "timestamp": "2024-01-15T10:30:00Z",
  "context": {
    "initiatingApplication": "mi-app-frontend",
    "loginSource": "Office365",
    "sessionScope": "specific",
    "notificationType": "targeted"
  },
  "data": {
    "userId": "123e4567-e89b-12d3-a456-426614174000",
    "email": "usuario@empresa.com",
    "displayName": "Juan Pérez",
    "loginType": "Office365",
    "ipAddress": "192.168.1.100",
    "roles": ["Admin", "User"],
    "permissions": [
      {
        "id": 1,
        "name": "users.read",
        "module": "Users",
        "action": "Read"
      }
    ]
  }
}
```

## 🛡️ Seguridad

### Verificación de Firma HMAC
```javascript
// En tu frontend, verifica la firma
const crypto = require('crypto');

function verifyWebhookSignature(payload, signature, secretKey) {
  const expectedSignature = crypto
    .createHmac('sha256', secretKey)
    .update(payload)
    .digest('hex')
    .toLowerCase();
    
  return signature === expectedSignature;
}

// En tu endpoint de webhook
app.post('/api/auth/webhook', (req, res) => {
  const signature = req.headers['x-webhook-signature'];
  const payload = JSON.stringify(req.body);
  
  if (!verifyWebhookSignature(payload, signature, 'tu-clave-secreta')) {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // Procesar la notificación de login
  const { data } = req.body;
  console.log(`Usuario ${data.email} se logueó con Office365`);
  
  // Actualizar estado de la aplicación, redirigir usuario, etc.
  res.json({ status: 'success' });
});
```

## 🔍 Logs y Monitoreo

Todos los envíos de webhook se registran en `NotificationLogs`:

```sql
SELECT 
    nl.WebhookUrl,
    nl.HttpStatusCode,
    nl.IsSuccess,
    nl.ResponseTime,
    nl.ErrorMessage,
    nl.CreatedAt
FROM auth.tbl_NotificationLogs nl
WHERE nl.EventType = 'Login'
ORDER BY nl.CreatedAt DESC;
```

## 🚀 Ejemplo Completo de Integración

### Frontend (React/JavaScript)
```javascript
// 1. Iniciar login con Office365
const startOffice365Login = async () => {
  const response = await fetch('/api/auth/azure/url?clientId=mi-app-frontend');
  const { url } = await response.json();
  window.location.href = url;
};

// 2. Endpoint para recibir notificaciones
app.post('/api/auth/webhook', (req, res) => {
  const { eventType, data } = req.body;
  
  if (eventType === 'Login') {
    // Usuario se logueó exitosamente
    localStorage.setItem('user', JSON.stringify(data));
    
    // Redirigir a dashboard o actualizar UI
    window.location.href = '/dashboard';
  }
  
  res.json({ status: 'received' });
});
```

Este es el flujo completo de cómo el sistema identifica qué aplicación frontend inició el login de Office365 y le envía la notificación correspondiente con los datos del usuario autenticado.

