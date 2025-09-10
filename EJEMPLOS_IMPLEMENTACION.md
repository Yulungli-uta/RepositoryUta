# Ejemplos Prácticos de Implementación

## 🔧 Ejemplo 1: Sistema ERP Legacy (C# .NET Framework)

### Registrar Webhook
```csharp
public async Task<bool> RegisterWebhook()
{
    var client = new HttpClient();
    client.DefaultRequestHeaders.Authorization = 
        new AuthenticationHeaderValue("Bearer", "tu-token-de-aplicacion");
    
    var request = new
    {
        applicationId = "10000000-0000-0000-0000-000000000001",
        eventType = "Login",
        webhookUrl = "https://erp.empresa.com/api/auth/webhook",
        secretKey = "erp-webhook-secret-2024"
    };
    
    var json = JsonConvert.SerializeObject(request);
    var content = new StringContent(json, Encoding.UTF8, "application/json");
    
    var response = await client.PostAsync(
        "https://auth.empresa.com/api/notifications/subscriptions", 
        content
    );
    
    return response.IsSuccessStatusCode;
}
```

### Recibir Notificaciones
```csharp
[HttpPost]
[Route("api/auth/webhook")]
public async Task<IActionResult> ReceiveAuthNotification([FromBody] WebhookPayload payload)
{
    try
    {
        // 1. Validar firma del webhook
        var signature = Request.Headers["X-Webhook-Signature"].FirstOrDefault();
        if (!ValidateWebhookSignature(payload, signature))
        {
            return Unauthorized(new { error = "Invalid signature" });
        }
        
        // 2. Procesar según tipo de evento
        switch (payload.EventType)
        {
            case "Login":
                await ProcessLoginEvent(payload.Data);
                break;
            case "Logout":
                await ProcessLogoutEvent(payload.Data);
                break;
            default:
                return BadRequest(new { error = "Unknown event type" });
        }
        
        return Ok(new { status = "processed", timestamp = DateTime.UtcNow });
    }
    catch (Exception ex)
    {
        // Log error pero devolver 200 para evitar reintentos innecesarios
        Logger.LogError(ex, "Error processing webhook");
        return Ok(new { status = "error", message = ex.Message });
    }
}

private bool ValidateWebhookSignature(WebhookPayload payload, string signature)
{
    if (string.IsNullOrEmpty(signature)) return false;
    
    var secretKey = "erp-webhook-secret-2024";
    var payloadJson = JsonConvert.SerializeObject(payload.Data);
    
    using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey)))
    {
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payloadJson));
        var expectedSignature = BitConverter.ToString(hash).Replace("-", "").ToLower();
        return signature.Equals(expectedSignature, StringComparison.OrdinalIgnoreCase);
    }
}

private async Task ProcessLoginEvent(dynamic loginData)
{
    var userId = Guid.Parse(loginData.userId.ToString());
    var email = loginData.email.ToString();
    var roles = ((JArray)loginData.roles).ToObject<string[]>();
    
    // Actualizar sesión en ERP
    await UpdateUserSession(userId, email, roles);
    
    // Registrar en log de auditoría
    await AuditLog.RecordAsync(new AuditEntry
    {
        UserId = userId,
        Action = "LOGIN_OFFICE365",
        Details = $"Usuario {email} autenticado vía Office365",
        Timestamp = DateTime.UtcNow,
        IpAddress = loginData.ipAddress?.ToString()
    });
    
    // Sincronizar permisos si es necesario
    if (loginData.permissions != null)
    {
        var permissions = ((JArray)loginData.permissions).ToObject<Permission[]>();
        await SyncUserPermissions(userId, permissions);
    }
}
```

## 🌐 Ejemplo 2: Portal Web (Node.js/Express)

### Registrar Webhook
```javascript
const axios = require('axios');

async function registerWebhook() {
    try {
        const response = await axios.post(
            'https://auth.empresa.com/api/notifications/subscriptions',
            {
                applicationId: '10000000-0000-0000-0000-000000000002',
                eventType: 'Login',
                webhookUrl: 'https://portal.empresa.com/api/notifications/login',
                secretKey: 'portal-webhook-secret-2024'
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.AUTH_TOKEN}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        console.log('Webhook registrado:', response.data);
        return true;
    } catch (error) {
        console.error('Error registrando webhook:', error.message);
        return false;
    }
}
```

### Recibir Notificaciones
```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// Middleware para validar firma
function validateWebhookSignature(req, res, next) {
    const signature = req.headers['x-webhook-signature'];
    const secretKey = 'portal-webhook-secret-2024';
    
    if (!signature) {
        return res.status(401).json({ error: 'Missing signature' });
    }
    
    const payloadJson = JSON.stringify(req.body.data);
    const expectedSignature = crypto
        .createHmac('sha256', secretKey)
        .update(payloadJson)
        .digest('hex');
    
    if (signature !== expectedSignature) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    
    next();
}

// Endpoint para recibir notificaciones de login
app.post('/api/notifications/login', validateWebhookSignature, async (req, res) => {
    try {
        const { eventType, data } = req.body;
        
        if (eventType === 'Login') {
            await processLoginNotification(data);
        }
        
        res.json({ status: 'processed', timestamp: new Date().toISOString() });
    } catch (error) {
        console.error('Error processing notification:', error);
        res.json({ status: 'error', message: error.message });
    }
});

async function processLoginNotification(loginData) {
    const { userId, email, displayName, loginType, roles, permissions } = loginData;
    
    // 1. Actualizar caché de usuario
    await redis.setex(`user:${userId}`, 3600, JSON.stringify({
        email,
        displayName,
        roles,
        permissions,
        lastLogin: new Date(),
        loginType
    }));
    
    // 2. Enviar notificación push si el usuario tiene la app móvil
    const deviceTokens = await getUserDeviceTokens(userId);
    if (deviceTokens.length > 0) {
        await sendPushNotification(deviceTokens, {
            title: 'Nuevo inicio de sesión',
            body: `Acceso desde ${loginType} detectado`,
            data: { userId, loginType }
        });
    }
    
    // 3. Actualizar estadísticas de uso
    await updateUserStats(userId, 'login', loginType);
    
    // 4. Verificar si necesita actualizar perfil
    const user = await User.findById(userId);
    if (!user.profileComplete) {
        await sendProfileCompletionReminder(userId);
    }
}
```

## 🐍 Ejemplo 3: API Python (Flask/FastAPI)

### Registrar Webhook
```python
import requests
import os

def register_webhook():
    url = "https://auth.empresa.com/api/notifications/subscriptions"
    headers = {
        "Authorization": f"Bearer {os.getenv('AUTH_TOKEN')}",
        "Content-Type": "application/json"
    }
    data = {
        "applicationId": "10000000-0000-0000-0000-000000000003",
        "eventType": "Login",
        "webhookUrl": "https://api.empresa.com/webhooks/auth/login",
        "secretKey": "api-webhook-secret-2024"
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        response.raise_for_status()
        print("Webhook registrado exitosamente")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error registrando webhook: {e}")
        return False
```

### Recibir Notificaciones (FastAPI)
```python
from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel
import hmac
import hashlib
import json
from typing import Optional, List, Dict, Any

app = FastAPI()

class WebhookPayload(BaseModel):
    eventType: str
    timestamp: str
    data: Dict[str, Any]
    signature: str

class LoginEventData(BaseModel):
    userId: str
    email: str
    displayName: str
    loginType: str
    ipAddress: Optional[str]
    loginTime: str
    roles: Optional[List[str]]
    permissions: Optional[List[Dict[str, Any]]]

def validate_webhook_signature(payload: str, signature: str) -> bool:
    secret_key = "api-webhook-secret-2024"
    expected_signature = hmac.new(
        secret_key.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

@app.post("/webhooks/auth/login")
async def receive_login_notification(
    request: Request,
    payload: WebhookPayload
):
    # Validar firma
    signature = request.headers.get("x-webhook-signature")
    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")
    
    payload_json = json.dumps(payload.data, sort_keys=True)
    if not validate_webhook_signature(payload_json, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    try:
        if payload.eventType == "Login":
            login_data = LoginEventData(**payload.data)
            await process_login_event(login_data)
        
        return {"status": "processed", "timestamp": payload.timestamp}
    
    except Exception as e:
        # Log error pero devolver 200 para evitar reintentos
        print(f"Error processing webhook: {e}")
        return {"status": "error", "message": str(e)}

async def process_login_event(login_data: LoginEventData):
    # 1. Actualizar base de datos
    await update_user_last_login(login_data.userId, login_data.loginTime)
    
    # 2. Sincronizar roles si es necesario
    if login_data.roles:
        await sync_user_roles(login_data.userId, login_data.roles)
    
    # 3. Registrar en analytics
    await record_login_analytics({
        "user_id": login_data.userId,
        "login_type": login_data.loginType,
        "ip_address": login_data.ipAddress,
        "timestamp": login_data.loginTime
    })
    
    # 4. Verificar políticas de seguridad
    await check_security_policies(login_data)

async def check_security_policies(login_data: LoginEventData):
    # Ejemplo: Verificar login desde IP sospechosa
    if login_data.ipAddress:
        is_suspicious = await check_suspicious_ip(login_data.ipAddress)
        if is_suspicious:
            await send_security_alert(login_data.userId, login_data.ipAddress)
```

## 📱 Ejemplo 4: Aplicación Móvil (React Native)

### Configurar Webhook Backend
```javascript
// backend/webhooks.js
const express = require('express');
const admin = require('firebase-admin');
const router = express.Router();

// Inicializar Firebase Admin
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

router.post('/auth/login', async (req, res) => {
    try {
        const { data } = req.body;
        const { userId, email, loginType } = data;
        
        // Obtener tokens de dispositivos del usuario
        const userDevices = await getUserDevices(userId);
        
        if (userDevices.length > 0) {
            const message = {
                notification: {
                    title: 'Nuevo inicio de sesión',
                    body: `Acceso detectado desde ${loginType}`,
                },
                data: {
                    type: 'login_notification',
                    userId: userId,
                    loginType: loginType,
                    timestamp: new Date().toISOString()
                },
                tokens: userDevices.map(device => device.fcmToken)
            };
            
            const response = await admin.messaging().sendMulticast(message);
            console.log('Notificaciones enviadas:', response.successCount);
        }
        
        res.json({ status: 'processed' });
    } catch (error) {
        console.error('Error:', error);
        res.json({ status: 'error', message: error.message });
    }
});
```

## 🔧 Ejemplo 5: Sistema Legacy (PHP)

```php
<?php
// webhook_handler.php

function validateWebhookSignature($payload, $signature, $secretKey) {
    $expectedSignature = hash_hmac('sha256', $payload, $secretKey);
    return hash_equals($signature, $expectedSignature);
}

function processLoginWebhook() {
    $headers = getallheaders();
    $signature = $headers['X-Webhook-Signature'] ?? '';
    $payload = file_get_contents('php://input');
    
    if (!validateWebhookSignature($payload, $signature, 'legacy-webhook-secret-2024')) {
        http_response_code(401);
        echo json_encode(['error' => 'Invalid signature']);
        return;
    }
    
    $data = json_decode($payload, true);
    
    if ($data['eventType'] === 'Login') {
        $loginData = $data['data'];
        
        // Actualizar sesión en base de datos
        updateUserSession($loginData['userId'], $loginData['roles']);
        
        // Registrar en log
        logUserActivity($loginData['userId'], 'LOGIN_OFFICE365', $loginData);
        
        // Sincronizar permisos
        syncUserPermissions($loginData['userId'], $loginData['permissions']);
    }
    
    echo json_encode(['status' => 'processed', 'timestamp' => date('c')]);
}

function updateUserSession($userId, $roles) {
    global $pdo;
    
    $stmt = $pdo->prepare("
        UPDATE user_sessions 
        SET roles = ?, last_activity = NOW() 
        WHERE user_id = ?
    ");
    $stmt->execute([json_encode($roles), $userId]);
}

function logUserActivity($userId, $action, $data) {
    global $pdo;
    
    $stmt = $pdo->prepare("
        INSERT INTO activity_log (user_id, action, data, created_at) 
        VALUES (?, ?, ?, NOW())
    ");
    $stmt->execute([$userId, $action, json_encode($data)]);
}

// Procesar webhook
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    processLoginWebhook();
}
?>
```

## 🧪 Script de Prueba

```bash
#!/bin/bash
# test_webhook.sh

# Configuración
AUTH_SERVER="https://auth.empresa.com"
WEBHOOK_URL="https://tu-sistema.com/webhook"
SECRET_KEY="tu-clave-secreta"

# 1. Registrar webhook
echo "Registrando webhook..."
curl -X POST "$AUTH_SERVER/api/notifications/subscriptions" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "applicationId": "tu-app-id",
    "eventType": "Login",
    "webhookUrl": "'$WEBHOOK_URL'",
    "secretKey": "'$SECRET_KEY'"
  }'

# 2. Probar webhook
echo "Probando webhook..."
curl -X POST "$AUTH_SERVER/api/notifications/webhook-test" \
  -H "Content-Type: application/json" \
  -d '{
    "test": "data",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  }'

# 3. Ver estadísticas
echo "Obteniendo estadísticas..."
curl -X GET "$AUTH_SERVER/api/notifications/stats" \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

## 📋 Checklist de Implementación

### ✅ Pasos Obligatorios

1. **Ejecutar script SQL**
   ```sql
   -- Database/centralizador_auth_changes.sql
   ```

2. **Registrar tu aplicación**
   ```http
   POST /api/notifications/subscriptions
   ```

3. **Implementar endpoint webhook**
   - Validar firma HMAC-SHA256
   - Procesar eventos de login
   - Devolver respuesta 200

4. **Configurar manejo de errores**
   - Logs detallados
   - Reintentos en tu lado si es necesario

5. **Probar la integración**
   - Usar endpoint de prueba
   - Verificar logs de notificaciones
   - Monitorear estadísticas

### 🔍 Verificación

```bash
# Verificar que las tablas se crearon
SELECT COUNT(*) FROM auth.tbl_NotificationSubscriptions;

# Verificar suscripciones activas
SELECT * FROM auth.vw_NotificationStats;

# Probar notificación manual
POST /api/notifications/process-pending
```

¡Con estos ejemplos puedes implementar la integración en cualquier tecnología! 🚀

