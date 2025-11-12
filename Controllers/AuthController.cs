using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;
    private readonly IAzureAuthService _azure;
    private readonly INotificationService _notificationService;

    public AuthController(IAuthService auth, IAzureAuthService azure, INotificationService notificationService)
    {
        _auth = auth;
        _azure = azure;
        _notificationService = notificationService;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req)
    {
        Console.WriteLine($"Login attempt for {req.Email}");
        var pair = await _auth.LoginLocalAsync(req.Email, req.Password);
        return pair is null ? Unauthorized(ApiResponse.Fail("Credenciales inválidas")) : Ok(ApiResponse.Ok(pair, "Login exitoso"));
    }

    [HttpPost("refresh")]
    [AllowAnonymous]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
    {
        var pair = await _auth.RefreshAsync(req.RefreshToken);
        return pair is null ? Unauthorized(ApiResponse.Fail("Refresh token inválido")) : Ok(ApiResponse.Ok(pair));
    }

    [HttpGet("azure/url")]
    [AllowAnonymous]
    public async Task<IActionResult> AzureUrl([FromQuery] string? clientId = null)
    {
        Console.WriteLine($"***************Azure URL requested with clientId: {clientId}");
        //clientId = "legacy-erp-client"; 10000000-0000-0000-0000-000000000001
        var (url, state) = await _azure.BuildAuthUrlAsync(clientId);
        //Console.WriteLine($"***************Azure auth URL generated: {url} with state {state}");
        return Ok(ApiResponse.Ok(new
        {
            url,
            state,
            clientId,
            message = clientId != null ? $"Login will notify {clientId}" : "Login will notify all applications"
        }));
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
        try
        {           

            // ✅ Decodificar state para obtener información de la aplicación
            var stateJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(state));
            var stateData = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(stateJson);
            var stateId = stateData.GetProperty("stateId").GetString();
            clientId = stateData.TryGetProperty("clientId", out var clientIdProp) && !clientIdProp.ValueKind.Equals(System.Text.Json.JsonValueKind.Null)
              ? clientIdProp.GetString()
              : null;
            //Console.WriteLine($"****************Extracted from state - StateId: {stateId}, ClientId: {clientId}");
        }
        catch (Exception ex)
        {
            //Console.WriteLine($"****************Error decoding state: {ex.Message}. Proceeding without clientId.");
        }
        var pair = await _azure.HandleCallbackAsync(code, state);
        Console.WriteLine($"******************Azure login processed. pair: {pair}, TokenPair: {(pair != null ? "Success" : "Failed")}");
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
                    Console.WriteLine($"***************ERROR: Token format is invalid. Expected 3 parts, got {tokenParts?.Length ?? 0}");
                    //Console.WriteLine($"***************Full token: {pair.AccessToken}");
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
                    Console.WriteLine($"***************Added {paddingNeeded} padding characters to payload");
                }
                Console.WriteLine($"***************Attempting to decode payload...");
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
                Console.WriteLine($"***************Payload JSON: {payloadJson}");
                // Deserializar el payload
                Dictionary<string, object>? tokenPayload = null;
                try
                {
                    tokenPayload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);
                    Console.WriteLine($"***************Payload deserialized successfully. Keys count: {tokenPayload?.Count ?? 0}");
                    if (tokenPayload != null)
                    {
                        Console.WriteLine("***************Available keys in token payload:");
                        foreach (var kvp in tokenPayload)
                        {
                            var valuePreview = kvp.Value?.ToString();
                            if (valuePreview?.Length > 100)
                                valuePreview = valuePreview.Substring(0, 100) + "...";
                            Console.WriteLine($" - {kvp.Key}: {valuePreview}");
                        }
                    }
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
                            //Console.WriteLine($"***************User ID parsed as GUID: {userId}");
                            //Console.WriteLine($"***************Preparing to send login notification for user {userId}");
                            Console.WriteLine($"***************Client IP: {clientIp}, User Agent: {userAgent}, " +
                                $"ClientId to notify: {clientId ?? "All applications"}");
                            if (!string.IsNullOrEmpty(clientId))
                            {
                                //Console.WriteLine($"*************Notifying specific application: {clientId}");
                                await _notificationService.NotifyLoginEventForApplicationAsync(
                                    userId, "Office365", clientIp, clientId, pair
                                );
                            }
                            else
                            {
                                //Console.WriteLine("*************Notifying all subscribed applications");
                                await _notificationService.NotifyLoginEventAsync(
                                    userId, "Office365", clientIp, null, null, pair
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
        Console.WriteLine($"Token validation request for token: {req.Token?[..Math.Min(10, req.Token?.Length ?? 0)]}...");
        if (string.IsNullOrEmpty(req.Token))
        {
            return BadRequest(ApiResponse.Fail("Token is required"));
        }
        //Console.WriteLine($"********** Auth- ValidateToken token{req.Token[..Math.Min(20, req.Token.Length)]}, clienid: {req.ClientId}");
        var result = await _auth.ValidateTokenAsync(req.Token, req.ClientId);
        Console.WriteLine("******** ValidateTokenAsync Response ********");
        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
        return Ok(ApiResponse.Ok(result, result.IsValid ? "Token válido" : "Token inválido"));
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
    {
        var sub = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (!Guid.TryParse(sub, out var userId))
            return Unauthorized(ApiResponse.Fail("Token inválido"));

        if (string.IsNullOrWhiteSpace(req.CurrentPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
            return BadRequest(ApiResponse.Fail("Las contraseñas son requeridas"));

        if (req.NewPassword.Length < 8)
            return BadRequest(ApiResponse.Fail("La nueva contraseña debe tener al menos 8 caracteres"));

        var success = await _auth.ChangePasswordAsync(userId, req.CurrentPassword, req.NewPassword);
        
        if (!success)
            return BadRequest(ApiResponse.Fail("No se pudo cambiar la contraseña. Verifique que la contraseña actual sea correcta y que sea un usuario local."));

        return Ok(ApiResponse.Ok(new ChangePasswordResponse(true, "Contraseña cambiada exitosamente")));
    }
}