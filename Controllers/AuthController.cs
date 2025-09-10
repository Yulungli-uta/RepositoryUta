using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
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
    _auth=auth; 
    _azure=azure; 
    _notificationService=notificationService;
  }

  [HttpPost("login")][AllowAnonymous][EnableRateLimiting("login")]
  public async Task<IActionResult> Login([FromBody] LoginRequest req){
    Console.WriteLine($"Login attempt for {req.Email}");
    var pair=await _auth.LoginLocalAsync(req.Email,req.Password);
    return pair is null ? Unauthorized(ApiResponse.Fail("Credenciales inválidas")) : Ok(ApiResponse.Ok(pair,"Login exitoso"));
  }

  [HttpPost("refresh")][AllowAnonymous]
  public async Task<IActionResult> Refresh([FromBody] RefreshRequest req){
    var pair=await _auth.RefreshAsync(req.RefreshToken);
    return pair is null ? Unauthorized(ApiResponse.Fail("Refresh token invÃ¡lido")) : Ok(ApiResponse.Ok(pair));
  }

  [HttpGet("azure/url")][AllowAnonymous]
  public async Task<IActionResult> AzureUrl(){ 
        var (url,state)=await _azure.BuildAuthUrlAsync(); 
        Console.WriteLine($"Azure auth URL generated: {url} with state {state}");
        return Ok(ApiResponse.Ok(new { url, state })); }

  [HttpGet("azure/callback")][AllowAnonymous]
  public async Task<IActionResult> AzureCallback([FromQuery] string code,[FromQuery] string state){
    Console.WriteLine($"Azure callback received. Code: {code}, State: {state}");
    
    // Obtener IP del cliente
    var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
    var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
    
    var pair=await _azure.HandleCallbackAsync(code,state);
    
    if (pair != null)
    {
      // ========== ENVIAR NOTIFICACIONES DE LOGIN OFFICE365 ==========
      try 
      {
        // Extraer información del usuario del token (esto es una simplificación)
        // En producción, podrías obtener el userId del token JWT o del contexto
        var tokenPayload = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(
          System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(pair.AccessToken.Split('.')[1] + "==")
          )
        );
        
        if (tokenPayload != null && tokenPayload.TryGetValue("sub", out var userIdObj))
        {
          if (Guid.TryParse(userIdObj.ToString(), out var userId))
          {
            // Enviar notificación de login
            await _notificationService.NotifyLoginEventAsync(
              userId, 
              "Office365", 
              clientIp, 
              null, // roles se obtienen internamente en el servicio
              null  // permisos se obtienen internamente en el servicio
            );
            
            Console.WriteLine($"Office365 login notification sent for user {userId}");
          }
        }
      }
      catch (Exception ex)
      {
        // Log error pero no fallar el login
        Console.WriteLine($"Error sending Office365 login notification: {ex.Message}");
      }
    }
    
    return pair is null ? Unauthorized(ApiResponse.Fail("No autorizado")) : Ok(ApiResponse.Ok(pair));
  }

  [HttpGet("me")][Authorize]
  public async Task<IActionResult> Me(){
    Console.WriteLine($"Fetching current user info { ClaimTypes.NameIdentifier}");
    var sub=User.FindFirstValue(ClaimTypes.NameIdentifier);
    Console.WriteLine($"valor Recuperado: {sub}");
    if(!Guid.TryParse(sub,out var id)) return Unauthorized(ApiResponse.Fail("Token inválido"));
    var me=await _auth.MeAsync(id);
    return me is null ? NotFound(ApiResponse.Fail("Usuario no encontrado")) : Ok(ApiResponse.Ok(me));
  }

  [HttpPost("validate-token")][AllowAnonymous]
  public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest req){
    Console.WriteLine($"Token validation request for token: {req.Token?[..Math.Min(10, req.Token?.Length ?? 0)]}...");
    
    if (string.IsNullOrEmpty(req.Token))
    {
      return BadRequest(ApiResponse.Fail("Token is required"));
    }
    
    var result = await _auth.ValidateTokenAsync(req.Token, req.ClientId);
    return Ok(ApiResponse.Ok(result, result.IsValid ? "Token válido" : "Token inválido"));
  }
}
