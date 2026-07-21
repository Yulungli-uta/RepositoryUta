// Controllers/FailedLoginsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

// Solo lectura: FailedLoginAttempt se escribe internamente (AuthRepository.RecordFailedAttemptAsync,
// llamado desde AuthService en cada intento fallido). Sin Delete vía API a propósito — es
// evidencia de fuerza bruta, no debe poder borrarse desde ningún cliente.
[ApiController, Route("api/failed-logins"), Authorize(Roles = "Administrador,R_DITIC")]
public class FailedLoginsController : ControllerBase
{
    private readonly ICrudService<FailedLoginAttempt, CreateFailedAttemptDto, UpdateFailedAttemptDto> _svc;
    public FailedLoginsController(ICrudService<FailedLoginAttempt, CreateFailedAttemptDto, UpdateFailedAttemptDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
