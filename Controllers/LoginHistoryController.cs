// Controllers/LoginHistoryController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

// Solo lectura: LoginHistory se escribe internamente (AuthRepository.InsertLoginAsync,
// llamado 7 veces desde AuthService en cada intento de login) — ningún flujo legítimo pasa
// por este controller. Los registros no se pueden alterar vía API, solo consultar.
[ApiController, Route("api/login-history"), Authorize(Roles = "Administrador,R_DITIC")]
public class LoginHistoryController : ControllerBase
{
    private readonly ICrudService<LoginHistory, CreateLoginHistoryDto, UpdateLoginHistoryDto> _svc;
    public LoginHistoryController(ICrudService<LoginHistory, CreateLoginHistoryDto, UpdateLoginHistoryDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
