using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/app-auth")]
public class AppAuthController : ControllerBase
{
    private readonly IAppAuthService _appAuthService;
    private readonly ILogger<AppAuthController> _logger;

    public AppAuthController(IAppAuthService appAuthService, ILogger<AppAuthController> logger)
    {
        _appAuthService = appAuthService;
        _logger = logger;
    }

    /// <summary>
    /// Autentica una aplicación cliente y devuelve un token de acceso
    /// </summary>
    /// <param name="request">Credenciales de la aplicación</param>
    /// <returns>Token de acceso para la aplicación</returns>
    [HttpPost("token")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> GetApplicationToken([FromBody] AppAuthRequest request)
    {
        try
        {
            _logger.LogInformation("Application token request for ClientId: {ClientId}", request.ClientId);
            
            var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
            
            var result = await _appAuthService.AuthenticateApplicationAsync(
                request.ClientId, 
                request.ClientSecret, 
                clientIp, 
                userAgent
            );
            
            if (result.Success)
            {
                _logger.LogInformation("Application authentication successful for ClientId: {ClientId}", request.ClientId);
                return Ok(ApiResponse.Ok(result, "Application authenticated successfully"));
            }
            else
            {
                _logger.LogWarning("Application authentication failed for ClientId: {ClientId}. Reason: {Message}", 
                    request.ClientId, result.Message);
                return Unauthorized(ApiResponse.Fail(result.Message));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during application authentication for ClientId: {ClientId}", request.ClientId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Autentica un usuario a través de una aplicación legacy
    /// </summary>
    /// <param name="request">Credenciales del usuario y aplicación</param>
    /// <returns>Información del usuario autenticado con roles y permisos</returns>
    [HttpPost("legacy-login")]
    [AllowAnonymous]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> LegacyLogin([FromBody] LegacyAuthRequest request)
    {
        try
        {
            _logger.LogInformation("Legacy authentication attempt for user: {Email} from application: {ClientId}", 
                request.UserEmail, request.ClientId);
            
            var clientIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
            
            var result = await _appAuthService.AuthenticateUserLegacyAsync(
                request.ClientId,
                request.ClientSecret,
                request.UserEmail,
                request.Password,
                request.IncludePermissions ?? true,
                clientIp,
                userAgent
            );
            
            if (result.Success)
            {
                _logger.LogInformation("Legacy authentication successful for user: {Email}", request.UserEmail);
                return Ok(ApiResponse.Ok(result, "User authenticated successfully"));
            }
            else
            {
                _logger.LogWarning("Legacy authentication failed for user: {Email}. Reason: {Message}", 
                    request.UserEmail, result.Message);
                return Unauthorized(ApiResponse.Fail(result.Message));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during legacy authentication for user: {Email}", request.UserEmail);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Valida un token JWT
    /// </summary>
    /// <param name="request">Token a validar</param>
    /// <returns>Información sobre la validez del token</returns>
    [HttpPost("validate-token")]
    [AllowAnonymous]
    public async Task<IActionResult> ValidateToken([FromBody] ValidateTokenRequest request)
    {
        try
        {
            _logger.LogInformation("Token validation request from ClientId: {ClientId}", request.ClientId);
            
            var result = await _appAuthService.ValidateTokenAsync(request.Token, request.ClientId);
            
            if (result.IsValid)
            {
                _logger.LogInformation("Token validation successful");
                return Ok(ApiResponse.Ok(result, "Token is valid"));
            }
            else
            {
                _logger.LogWarning("Token validation failed. Reason: {Message}", result.Message);
                return Ok(ApiResponse.Ok(result, "Token validation result"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token validation");
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Obtiene estadísticas de uso de una aplicación (solo para administradores)
    /// </summary>
    /// <param name="clientId">ID de la aplicación cliente</param>
    /// <returns>Estadísticas de uso</returns>
    [HttpGet("stats/{clientId}")]
    [Authorize]
    public async Task<IActionResult> GetApplicationStats(string clientId)
    {
        try
        {
            _logger.LogInformation("Application stats request for ClientId: {ClientId}", clientId);
            
            var stats = await _appAuthService.GetApplicationStatsAsync(clientId);
            
            if (stats != null)
            {
                return Ok(ApiResponse.Ok(stats, "Application statistics retrieved"));
            }
            else
            {
                return NotFound(ApiResponse.Fail("Application not found"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving application stats for ClientId: {ClientId}", clientId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }
}

