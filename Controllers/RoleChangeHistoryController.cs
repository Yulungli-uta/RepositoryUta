// Controllers/RoleChangeHistoryController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

// Solo lectura: RoleChangeHistory se escribe internamente (UserRoleService, al asignar/
// reasignar/revocar un rol vía UserRolesController) — este controller nunca participa en
// esa escritura. Los registros no se pueden alterar vía API, solo consultar.
[ApiController, Route("api/role-change-history"), Authorize(Roles = "Administrador,R_DITIC")]
public class RoleChangeHistoryController : ControllerBase
{
    private readonly ICrudService<RoleChangeHistory, CreateRoleChangeHistoryDto, UpdateRoleChangeHistoryDto> _svc;
    public RoleChangeHistoryController(ICrudService<RoleChangeHistory, CreateRoleChangeHistoryDto, UpdateRoleChangeHistoryDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
