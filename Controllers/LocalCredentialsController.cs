// Controllers/LocalCredentialsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/local-credentials"), Authorize(Roles = "Administrador,R_DITIC")]
public class LocalCredentialsController : ControllerBase
{
    private readonly ICrudService<LocalUserCredential, CreateLocalCredentialDto, UpdateLocalCredentialDto> _svc;
    private readonly IUserRepository _users;
    private readonly IAuditService _audit;
    private readonly IAppClock _clock;

    public LocalCredentialsController(
        ICrudService<LocalUserCredential, CreateLocalCredentialDto, UpdateLocalCredentialDto> svc,
        IUserRepository users,
        IAuditService audit,
        IAppClock clock)
    {
        _svc = svc;
        _users = users;
        _audit = audit;
        _clock = clock;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateLocalCredentialDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateLocalCredentialDto dto)
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    /// <summary>
    /// Desbloquea una cuenta Local: reinicia los intentos fallidos y levanta el bloqueo. Queda en la auditoría.
    /// Se usa este endpoint y no el PUT genérico porque ese mapea los campos nulos sobre la credencial.
    /// </summary>
    [HttpPost("{id:guid}/unlock")]
    public async Task<IActionResult> Unlock(Guid id)
    {
        var cred = await _users.GetLocalCredAsync(id);
        if (cred is null) return NotFound(ApiResponse.Fail("No existe"));

        var wasLocked = cred.IsLocked || (cred.LockedUntil.HasValue && cred.LockedUntil.Value > _clock.Now);
        cred.FailedAttempts = 0;
        cred.IsLocked = false;
        cred.LockedUntil = null;
        await _users.UpdateLocalCredAsync(cred);

        var actor = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue("email") ?? "desconocido";
        await _audit.LogAsync("AccountUnlocked", "Authentication", id.ToString(),
            oldValues: wasLocked ? "Locked" : "NotLocked", newValues: $"UnlockedBy={actor}", userId: id);
        return Ok(ApiResponse.Ok(new { unlocked = true, wasLocked }));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
