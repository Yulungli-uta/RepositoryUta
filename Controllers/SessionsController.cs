// Controllers/SessionsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

// Solo lectura: UserSession se escribe internamente (AuthRepository.CreateSessionAsync,
// llamado desde AuthService en login/refresh) — ningún flujo legítimo pasa por este
// controller para crear/modificar/borrar sesiones. La revocación real vive en
// SessionManagementController (Administrador,R_DITIC). Igual que AuditLogController: los
// registros no se pueden alterar vía API, solo consultar.
[ApiController, Route("api/sessions"), Authorize(Roles = "Administrador,R_DITIC")]
public class SessionsController : ControllerBase
{
    private readonly ICrudService<UserSession, CreateUserSessionDto, UpdateUserSessionDto> _svc;
    public SessionsController(ICrudService<UserSession, CreateUserSessionDto, UpdateUserSessionDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
