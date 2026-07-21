using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Gestión de sesiones activas de usuarios y clientes API.
/// Permite listar, revocar sesiones y administrar clientes API (toggle + rotate secret).
/// </summary>
[ApiController, Route("api/session-management"), Authorize(Roles = "Administrador,R_DITIC")]
public class SessionManagementController : ControllerBase
{
    private readonly ISessionManagementService _svc;

    public SessionManagementController(ISessionManagementService svc) => _svc = svc;

    private string CurrentUser =>
        User.FindFirstValue(ClaimTypes.Email)
        ?? User.FindFirstValue("email")
        ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? "unknown";

    // ── Sesiones de usuario ────────────────────────────────────────────────────

    /// <summary>Lista todas las sesiones de usuario activas y no expiradas.</summary>
    [HttpGet("sessions")]
    public async Task<IActionResult> GetActiveSessions(CancellationToken ct)
        => Ok(ApiResponse.Ok(await _svc.GetActiveSessionsAsync(ct)));

    /// <summary>Revoca una sesión específica y envía ForceLogout vía SignalR si el usuario está conectado.</summary>
    [HttpPost("sessions/{sessionId:guid}/revoke")]
    public async Task<IActionResult> RevokeSession(Guid sessionId, CancellationToken ct)
    {
        try
        {
            var result = await _svc.RevokeSessionAsync(sessionId, CurrentUser, ct);
            return Ok(ApiResponse.Ok(result));
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>Revoca todas las sesiones activas de un usuario.</summary>
    [HttpPost("sessions/user/{userId:guid}/revoke-all")]
    public async Task<IActionResult> RevokeAllUserSessions(Guid userId, CancellationToken ct)
    {
        var count = await _svc.RevokeAllUserSessionsAsync(userId, CurrentUser, ct);
        return Ok(ApiResponse.Ok(new { RevokedCount = count }, $"{count} sesión(es) revocada(s)."));
    }

    // ── Clientes API ───────────────────────────────────────────────────────────

    /// <summary>Lista todos los clientes API con estadísticas de uso.</summary>
    [HttpGet("api-clients")]
    public async Task<IActionResult> GetApiClients(CancellationToken ct)
        => Ok(ApiResponse.Ok(await _svc.GetActiveApiClientsAsync(ct)));

    /// <summary>Activa o suspende un cliente API.</summary>
    [HttpPost("api-clients/{applicationId:guid}/toggle")]
    public async Task<IActionResult> ToggleClient(Guid applicationId, CancellationToken ct)
    {
        try
        {
            var result = await _svc.ToggleClientAsync(applicationId, CurrentUser, ct);
            return Ok(ApiResponse.Ok(result, result.Message));
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Rota el ClientSecret de un cliente API.
    /// El nuevo secret se devuelve en texto plano una sola vez.
    /// </summary>
    [HttpPost("api-clients/{applicationId:guid}/rotate-secret")]
    public async Task<IActionResult> RotateSecret(Guid applicationId, CancellationToken ct)
    {
        try
        {
            var result = await _svc.RotateSecretAsync(applicationId, CurrentUser, ct);
            return Ok(ApiResponse.Ok(result, "Secret rotado. Guarde el nuevo valor — no se volverá a mostrar."));
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(ApiResponse.Fail(ex.Message));
        }
    }
}
