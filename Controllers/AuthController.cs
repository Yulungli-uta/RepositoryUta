using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using System.Net;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;
    private readonly IAzureAuthService _azure;
    private readonly IAzureManagementService _azureMgmt;
    private readonly IUserRepository _users;
    private readonly INotificationService _notificationService;
    private readonly IIdentityProviderResolver _identityResolver;
    private readonly IConfiguration _cfg;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IAuthService auth,
        IAzureAuthService azure,
        IAzureManagementService azureMgmt,
        IUserRepository users,
        INotificationService notificationService,
        IIdentityProviderResolver identityResolver,
        IConfiguration cfg,
        ILogger<AuthController> logger)
    {
        _auth = auth;
        _azure = azure;
        _azureMgmt = azureMgmt;
        _users = users;
        _notificationService = notificationService;
        _identityResolver = identityResolver;
        _cfg = cfg;
        _logger = logger;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        var ip = GetClientIp();
        var ua = GetUserAgent();
        var device = GetDeviceInfo();

        var pair = await _auth.LoginLocalAsync(req.Email, req.Password, ipAddress: ip, userAgent: ua, deviceInfo: device);
        return pair is null ? Unauthorized(ApiResponse.Fail("Credenciales inválidas")) : Ok(ApiResponse.Ok(pair, "Login exitoso"));
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
    {
        var pair = await _auth.RefreshAsync(req.RefreshToken);
        return pair is null ? Unauthorized(ApiResponse.Fail("Refresh token inválido")) : Ok(ApiResponse.Ok(pair));
    }

    /// <summary>
    /// Cierra la sesión revocando el refresh token en servidor.
    /// AllowAnonymous porque el access token puede estar ya expirado al momento del logout;
    /// la credencial es el propio refresh token. Idempotente y sin revelar si el token
    /// era válido: siempre responde éxito (LogoutAsync ya se comporta así).
    /// </summary>
    [HttpPost("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout([FromBody] RefreshRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.RefreshToken))
            return BadRequest(ApiResponse.Fail("Refresh token requerido"));

        await _auth.LogoutAsync(req.RefreshToken);
        return Ok(ApiResponse.Ok(true, "Sesión cerrada"));
    }

    [HttpGet("azure/url")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AzureUrlGet(
        [FromQuery] string? clientId = null,
        [FromQuery] string? browserId = null,
        [FromQuery] string? codeChallenge = null)
    {
        try
        {
            var (url, state) = await _azure.BuildAuthUrlAsync(clientId, browserId, codeChallenge);
            return Ok(ApiResponse.Ok(new
            {
                url,
                state,
                clientId,
                browserId,
                message = $"Login habilitado para la aplicación {clientId}"
            }));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ApiResponse.Fail(ex.Message));
        }
    }

    [HttpPost("azure/url")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AzureUrlPost([FromBody] AzureAuthUrlRequest req)
    {
        try
        {
            var (url, state) = await _azure.BuildAuthUrlAsync(req.ClientId, req.BrowserId, req.CodeChallenge);
            return Ok(ApiResponse.Ok(new
            {
                url,
                state,
                clientId = req.ClientId,
                browserId = req.BrowserId,
                message = $"Login habilitado para la aplicación {req.ClientId}"
            }));
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Canjea un deliveryCode PKCE (RFC 7636) por el par de tokens real. Solo la pestaña
    /// que generó el codeVerifier original (nunca transmitido hasta este momento) puede
    /// completar el intercambio. AllowAnonymous porque la credencial es el propio
    /// codeVerifier, igual que /refresh usa el refresh token como credencial.
    /// </summary>
    [HttpPost("azure/exchange")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> AzureExchange([FromBody] AzureExchangeRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.DeliveryCode) || string.IsNullOrWhiteSpace(req.CodeVerifier))
            return BadRequest(ApiResponse.Fail("deliveryCode y codeVerifier son requeridos"));

        var pair = await _azure.ExchangeDeliveryCodeAsync(req.DeliveryCode, req.CodeVerifier);
        return pair is null
            ? Unauthorized(ApiResponse.Fail("Código de entrega inválido o expirado"))
            : Ok(ApiResponse.Ok(pair));
    }

    [HttpGet("azure/callback")]
    [AllowAnonymous]
    public async Task<IActionResult> AzureCallback([FromQuery] string code, [FromQuery] string state)
    {
        //Console.WriteLine($"*******************Azure callback received. Code: {code}, State: {state}");
        // Obtener IP del cliente
        var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
        var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
        string? clientId = null;
        string? browserId = null;
        try
        {           

            // ✅ Decodificar state para obtener información de la aplicación
            var stateJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(state));
            var stateData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(stateJson);
            var stateId = stateData.GetProperty("stateId").GetString();
            clientId = stateData.TryGetProperty("clientId", out var clientIdProp) && !clientIdProp.ValueKind.Equals(System.Text.Json.JsonValueKind.Null)
              ? clientIdProp.GetString()
              : null;
            browserId = stateData.TryGetProperty("browserId", out var browserIdProp) && browserIdProp.ValueKind != JsonValueKind.Null
                ? browserIdProp.GetString()
                : null;
            //Console.WriteLine($"****************Extracted from state - StateId: {stateId}, ClientId: {clientId}");
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"****************Error decoding state: {ex.Message}. Proceeding without clientId.");
        }
        // Interruptor operativo: permite revertir al instante (sin recompilar) al reparto
        // directo de tokens por WebSocket si el flujo PKCE presentara algún problema en
        // producción. Default true si la clave falta o no es parseable — el valor real
        // queda siempre explícito en appsettings.json.
        var secureTokenDelivery = bool.TryParse(_cfg["AzureAd:SecureTokenDelivery"], out var std) ? std : true;

        TokenPair? pair;
        string? deliveryCode = null;
        try
        {
            if (secureTokenDelivery)
            {
                (pair, deliveryCode) = await _azure.CompleteLoginAndIssueDeliveryCodeAsync(code, state);
            }
            else
            {
                pair = await _azure.HandleCallbackAsync(code, state);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning(
                "[AZURE-LOGIN] Callback rechazado ({Message}). ClientId={ClientId}, BrowserId={BrowserId}",
                ex.Message, clientId, browserId);
            return Content(
                $"<html><body><h3>Acceso no autorizado</h3><p>{ex.Message}</p><script>setTimeout(()=>window.close(),3000);</script></body></html>",
                "text/html");
        }
        catch (Exception ex)
        {
            // Cubre fallas no anticipadas (MSAL/AcquireTokenByAuthorizationCode, Graph API,
            // consulta a AD, etc.) que antes se propagaban al manejador global de excepciones
            // y devolvían un 500 JSON crudo dentro del popup — sin script de cierre, sin
            // mensaje entendible, y sin quedar claro que el error ocurrió en el callback de
            // Azure. Ahora se responde con la misma página de cierre que el resto de casos de
            // esta acción, y el detalle real queda solo en el log (nunca se expone al cliente).
            _logger.LogError(ex,
                "[AZURE-LOGIN] Error inesperado procesando el callback de Azure. ClientId={ClientId}, BrowserId={BrowserId}, TraceId={TraceId}",
                clientId, browserId, HttpContext.TraceIdentifier);
            return Content(
                $"<html><body><h3>Ocurrió un error inesperado</h3><p>No se pudo completar el inicio de sesión. Cierra esta ventana e intenta de nuevo.</p><p style=\"font-size:11px;color:#888\">Referencia: {HttpContext.TraceIdentifier}</p><script>setTimeout(()=>window.close(),3000);</script></body></html>",
                "text/html");
        }
        //Console.WriteLine($"******************Azure login processed. pair: {pair}, TokenPair: {(pair != null ? "Success" : "Failed")}");
        if (pair != null)
        {
            // ========== DEBUG Y ENVIAR NOTIFICACIONES DE LOGIN OFFICE365 ==========
            try
            {
                //Console.WriteLine($"***************Starting notification process...");
                //Console.WriteLine($"***************AccessToken length: {pair.AccessToken?.Length ?? 0}");
                //Console.WriteLine($"***************AccessToken starts with: {pair.AccessToken?.Substring(0, Math.Min(50, pair.AccessToken.Length ?? 0))}");
                // Verificar que el token tiene el formato JWT esperado (3 partes separadas por puntos)
                var tokenParts = pair.AccessToken?.Split('.');
                //Console.WriteLine($"***************Token parts count: {tokenParts?.Length ?? 0}");
                if (tokenParts == null || tokenParts.Length != 3)
                {
                    // Continuar con el login pero sin notificación
                    //return Ok(ApiResponse.Ok(pair));
                }
                //Console.WriteLine($"***************Token header: {tokenParts[0]}");
                //Console.WriteLine($"***************Token payload (base64): {tokenParts[1]}");
                //Console.WriteLine($"***************Token signature: {tokenParts[2].Substring(0, Math.Min(20, tokenParts[2].Length))}...");
                // Agregar padding si es necesario para el Base64
                var payloadBase64 = tokenParts[1];
                var paddingNeeded = (4 - (payloadBase64.Length % 4)) % 4;
                if (paddingNeeded > 0)
                {
                    payloadBase64 += new string('=', paddingNeeded);
                    //Console.WriteLine($"***************Added {paddingNeeded} padding characters to payload");
                }
                //Console.WriteLine($"***************Attempting to decode payload...");
                // Decodificar el payload del JWT
                byte[] payloadBytes;
                try
                {
                    payloadBytes = Convert.FromBase64String(payloadBase64);
                    //Console.WriteLine($"***************Payload decoded successfully. Bytes length: {payloadBytes.Length}");
                }
                catch (Exception decodeEx)
                {
                    //Console.WriteLine($"***************ERROR decoding base64 payload: {decodeEx.Message}");
                    //return Ok(ApiResponse.Ok(pair));
                    return Content("<html><body>Error en decodificación. Cierre esta ventana.</body></html>", "text/html");
                }
                var payloadJson = System.Text.Encoding.UTF8.GetString(payloadBytes);
                //Console.WriteLine($"***************Payload JSON: {payloadJson}");
                // Deserializar el payload
                Dictionary<string, object>? tokenPayload = null;
                try
                {
                    tokenPayload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
                    //Console.WriteLine($"***************Payload deserialized successfully. Keys count: {tokenPayload?.Count ?? 0}");
                    // (claims del payload disponibles en tokenPayload si se necesitan más abajo)
                }
                catch (Exception parseEx)
                {
                    //Console.WriteLine($"***************ERROR parsing payload JSON: {parseEx.Message}");
                    //return Ok(ApiResponse.Ok(pair));
                    return Content("<html><body>Error en parseo. Cierre esta ventana.</body></html>", "text/html");
                }
                if (tokenPayload != null)
                {
                    // Buscar diferentes campos que podrían contener el user ID
                    var possibleUserIdFields = new[] { "sub", "oid", "unique_name", "upn", "email", "preferred_username", // };
                                            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"};
                    //Console.WriteLine($"***************Searching for user ID in token payload...");
                    string? foundUserId = null;
                    string? foundUserIdField = null;
                    foreach (var field in possibleUserIdFields)
                    {
                        if (tokenPayload.TryGetValue(field, out var userIdObj) && userIdObj != null)
                        {
                            var userIdStr = userIdObj.ToString();
                            //Console.WriteLine($"***************Found {field}: {userIdStr}");
                            if (!string.IsNullOrWhiteSpace(userIdStr))
                            {
                                foundUserId = userIdStr;
                                foundUserIdField = field;
                                break; // Usar el primer campo no vacío encontrado
                            }
                        }
                    }
                    if (!string.IsNullOrWhiteSpace(foundUserId))
                    {
                        //Console.WriteLine($"***************Using user ID from field '{foundUserIdField}': {foundUserId}");
                        // Intentar convertir a GUID si es posible, sino usar como string
                        if (Guid.TryParse(foundUserId, out var userId))
                        {
                            if (!string.IsNullOrEmpty(clientId))
                            {
                                //Console.WriteLine($"*************Notifying specific application: {clientId}");
                                await _notificationService.NotifyLoginEventForApplicationAsync(
                                    userId, "Office365", clientIp, clientId, pair, browserId ?? "", deliveryCode
                                );
                            }
                            else
                            {
                                //Console.WriteLine("*************Notifying all subscribed applications");
                                await _notificationService.NotifyLoginEventAsync(
                                    userId, "Office365", clientIp, null, null, pair, browserId ?? ""
                                );
                            }
                            //Console.WriteLine($"***************Office365 login notification sent for user {userId}");
                        }
                        else
                        {
                            //Console.WriteLine($"***************User ID could not be parsed as GUID: {foundUserId}");
                            //Console.WriteLine($"***************Notification service might need to support string user IDs");
                            // Si tu servicio de notificaciones puede manejar strings en lugar de GUIDs,
                            // podrías intentar la notificación aquí también
                        }
                    }
                    else
                    {
                        //Console.WriteLine($"***************No user ID found in any of the expected fields");
                        //Console.WriteLine($"***************Token might be from a different provider or have a different structure");
                    }
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"***************ERROR in notification process: {ex.Message}");
                //Console.WriteLine($"***************Stack trace: {ex.StackTrace}");
                // Log error pero no fallar el login
            }
        }
        else
        {
            //Console.WriteLine($"***************TokenPair is null - login failed");
        }

        if (pair is null) return Unauthorized(ApiResponse.Fail("No autorizado"));

        // Retornar HTML que cierra la ventana popup
        var html = @"
        <html>
        <body>
        <script>
          setTimeout(function() {
            window.close();
          }, 500);
        </script>
        Autenticación completada. Cerrando ventana...
        </body>
        </html>
        ";
        return Content(html, "text/html");
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> Me()
    {
        //Console.WriteLine($"Fetching current user info {ClaimTypes.NameIdentifier}");
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        //Console.WriteLine($"valor Recuperado: {sub}");
        if (!Guid.TryParse(sub, out var id)) return Unauthorized(ApiResponse.Fail("Token inválido"));
        var me = await _auth.MeAsync(id);
        return me is null ? NotFound(ApiResponse.Fail("Usuario no encontrado")) : Ok(ApiResponse.Ok(me));
    }

    [HttpPost("validate-token")]
    [AllowAnonymous]
    public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest req)
    {
        //Console.WriteLine($"Token validation request for token: {req.Token?[..Math.Min(10, req.Token?.Length ?? 0)]}...");
        //Console.WriteLine($"Token validation request for token Real: {req.Token}");
        //_logger.LogInformation($"Token completo: {req.Token}");
        if (string.IsNullOrEmpty(req.Token))
        {
            return BadRequest(ApiResponse.Fail("Token is required"));
        }
        //Console.WriteLine($"********** Auth- ValidateToken token{req.Token[..Math.Min(20, req.Token.Length)]}, clienid: {req.ClientId}");
        var result = await _auth.ValidateTokenAsync(req.Token, req.ClientId);
        //Console.WriteLine("******** ValidateTokenAsync Response ********");
        //Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions
        //{
        //    WriteIndented = true
        //}));
        return Ok(ApiResponse.Ok(result, result.IsValid ? "Token válido" : "Token inválido"));
    }

    /// <summary>
    /// Cambio de contraseña simple: requiere contraseña actual + nueva.
    /// Mínimo 8 caracteres, una mayúscula y un número.
    /// </summary>
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(ApiResponse.Fail("Token inválido"));

        if (string.IsNullOrWhiteSpace(req.NewPassword))
            return BadRequest(ApiResponse.Fail("La nueva contraseña es requerida"));

        var user = await _users.FindByIdAsync(userId);
        if (user is null || !user.IsActive)
            return BadRequest(ApiResponse.Fail("Usuario no encontrado o inactivo"));

        if (string.Equals(user.UserType, "AzureAD", StringComparison.OrdinalIgnoreCase))
        {
            var method = _cfg["PasswordChange:Method"] ?? "AzureWriteback";

            if (string.Equals(method, "LocalAd", StringComparison.OrdinalIgnoreCase))
            {
                var (ok, msg) = await ChangePasswordViaLocalAdAsync(user, req.CurrentPassword, req.NewPassword);
                return ok ? Ok(ApiResponse.Ok(new ChangePasswordResponse(true, msg))) : BadRequest(ApiResponse.Fail(msg));
            }

            // AzureWriteback: requiere ObjectId configurado
            if (user.AzureObjectId is null)
                return BadRequest(ApiResponse.Fail("El usuario no tiene un ObjectId de Azure asociado. Configure PasswordChange:Method=LocalAd como alternativa."));

            var azureOk = await _azureMgmt.ChangePasswordInAzureAsync(
                user.AzureObjectId.Value.ToString(), req.NewPassword, forceChangeNextSignIn: false);

            return azureOk
                ? Ok(ApiResponse.Ok(new ChangePasswordResponse(true, "Contraseña cambiada exitosamente en Office 365")))
                : BadRequest(ApiResponse.Fail("No se pudo cambiar la contraseña en Office 365. Verifique que cumpla los requisitos de la política."));
        }

        // Usuario local: requiere contraseña actual para verificación
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
            return BadRequest(ApiResponse.Fail("La contraseña actual es requerida para usuarios locales"));

        var result = await _auth.ChangePasswordAsync(userId, req.CurrentPassword, req.NewPassword);

        if (!result.Success)
            return BadRequest(ApiResponse.Fail(result.Message));

        return Ok(ApiResponse.Ok(result));
    }

    /// <summary>
    /// Paso 1 del cambio de contraseña con doble factor: genera un OTP de 6 dígitos válido 10 minutos.
    /// En producción el código llega por email/SMS. En desarrollo se retorna en la respuesta.
    /// </summary>
    [HttpPost("request-password-change-2fa")]
    [Authorize]
    public async Task<IActionResult> RequestPasswordChange2FA()
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(ApiResponse.Fail("Token inválido"));

        var isDev = HttpContext.RequestServices
            .GetRequiredService<IWebHostEnvironment>().IsDevelopment();

        var result = await _auth.RequestPasswordChange2FAAsync(userId, isDev);

        if (!result.Success)
            return BadRequest(ApiResponse.Fail(result.Message));

        return Ok(ApiResponse.Ok(result, result.Message));
    }

    /// <summary>
    /// Paso 2 del cambio de contraseña con doble factor.
    /// Usuarios locales: requiere OTP + contraseña actual + nueva contraseña.
    /// Usuarios AzureAD: requiere OTP + nueva contraseña (sin contraseña actual; se aplica directo en Azure AD).
    /// </summary>
    [HttpPost("change-password-2fa")]
    [Authorize]
    public async Task<IActionResult> ChangePasswordWith2FA([FromBody] ChangePasswordWith2FARequest req)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(ApiResponse.Fail("Token inválido"));

        if (string.IsNullOrWhiteSpace(req.NewPassword) || string.IsNullOrWhiteSpace(req.OtpCode))
            return BadRequest(ApiResponse.Fail("La nueva contraseña y el código OTP son requeridos"));

        var user = await _users.FindByIdAsync(userId);
        if (user is null || !user.IsActive)
            return BadRequest(ApiResponse.Fail("Usuario no encontrado o inactivo"));

        // ── Flujo AzureAD: verificar OTP, luego cambiar según método configurado ──
        if (string.Equals(user.UserType, "AzureAD", StringComparison.OrdinalIgnoreCase))
        {
            // OTP siempre se verifica primero independientemente del método
            var otpResult = await _auth.VerifyAndConsumePasswordOtpAsync(userId, req.OtpCode);
            if (!otpResult.Success)
                return BadRequest(ApiResponse.Fail(otpResult.Message));

            var method = _cfg["PasswordChange:Method"] ?? "AzureWriteback";

            if (string.Equals(method, "LocalAd", StringComparison.OrdinalIgnoreCase))
            {
                var (ok, msg) = await ChangePasswordViaLocalAdAsync(user, req.CurrentPassword, req.NewPassword);
                return ok ? Ok(ApiResponse.Ok(new ChangePasswordResponse(true, msg))) : BadRequest(ApiResponse.Fail(msg));
            }

            // AzureWriteback
            if (user.AzureObjectId is null)
                return BadRequest(ApiResponse.Fail("El usuario no tiene un ObjectId de Azure asociado. Configure PasswordChange:Method=LocalAd como alternativa."));

            var azureOk = await _azureMgmt.ChangePasswordInAzureAsync(
                user.AzureObjectId.Value.ToString(), req.NewPassword, forceChangeNextSignIn: false);

            return azureOk
                ? Ok(ApiResponse.Ok(new ChangePasswordResponse(true, "Contraseña cambiada exitosamente en Office 365 con verificación 2FA")))
                : BadRequest(ApiResponse.Fail("No se pudo cambiar la contraseña en Office 365. Verifique que cumpla los requisitos de la política."));
        }

        // ── Flujo Local: OTP + contraseña actual requerida ───────────────────
        if (string.IsNullOrWhiteSpace(req.CurrentPassword))
            return BadRequest(ApiResponse.Fail("La contraseña actual es requerida para usuarios locales"));

        var result = await _auth.ChangePasswordWith2FAAsync(userId, req.CurrentPassword, req.NewPassword, req.OtpCode);
        if (!result.Success)
            return BadRequest(ApiResponse.Fail(result.Message));

        return Ok(ApiResponse.Ok(result, result.Message));
    }

    /// <summary>
    /// Devuelve el método de cambio de contraseña configurado para AzureAD users.
    /// "LocalAd" = cambia en AD local (sin Password Writeback).
    /// "AzureWriteback" = cambia vía Graph API en Azure AD.
    /// </summary>
    [HttpGet("password-change-method")]
    [AllowAnonymous]
    public IActionResult GetPasswordChangeMethod()
    {
        var method = _cfg["PasswordChange:Method"] ?? "AzureWriteback";
        return Ok(ApiResponse.Ok(new { method }));
    }

    /// <summary>
    /// Verifica la contraseña actual del usuario contra el AD Local y cambia la contraseña
    /// usando la cuenta de servicio + LDAPS. No requiere Password Writeback.
    /// </summary>
    private async Task<(bool Success, string Message)> ChangePasswordViaLocalAdAsync(
        WsSeguUta.AuthSystem.API.Models.Entities.User user, string? currentPassword, string newPassword)
    {
        if (string.IsNullOrWhiteSpace(currentPassword))
            return (false, "La contraseña actual es requerida para cambio vía AD Local");

        try
        {
            // 1. Verificar contraseña actual via LDAP bind
            var provider = _identityResolver.GetProvider("LocalAd");
            var authResult = await provider.AuthenticateAsync(
                new ProviderAuthRequest("LocalAd", user.Email, currentPassword));

            if (!authResult.Success)
                return (false, "La contraseña actual es incorrecta");

            // 2. Buscar usuario en AD para obtener el objectGUID
            var dir = _identityResolver.GetDirectory("LocalAd");
            var adUser = await dir.GetUserByEmailAsync(user.Email);
            if (adUser is null)
                return (false, "Usuario no encontrado en Active Directory local. Contacte al administrador.");

            // 3. Cambiar contraseña via cuenta de servicio + LDAPS
            await dir.ChangeUserPasswordAsync(adUser.Id, newPassword, false);

            return (true, "Contraseña cambiada exitosamente en Active Directory local");
        }
        catch (Exception ex)
        {
            return (false, $"Error al cambiar contraseña en AD Local: {ex.Message}");
        }
    }

    private string? GetClientIp()
    {
        // Si estás detrás de proxy / gateway, esto suele venir poblado
        var xff = Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
            return xff.Split(',')[0].Trim();

        var xRealIp = Request.Headers["X-Real-IP"].ToString();
        if (!string.IsNullOrWhiteSpace(xRealIp))
            return xRealIp.Trim();

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

        // Normaliza loopback IPv6 a 127.0.0.1 (útil en dev)
        if (ip == "::1") return "127.0.0.1";

        return ip;
    }

    private string? GetUserAgent()
        => Request.Headers["User-Agent"].ToString();

    private string? GetDeviceInfo()
    {
        // opcional: tu front/cliente puede enviar algo como:
        // "Chrome 120 | Windows 11 | Laptop"
        var device = Request.Headers["X-Device-Info"].ToString();
        return string.IsNullOrWhiteSpace(device) ? null : device;
    }
}