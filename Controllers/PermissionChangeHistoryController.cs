// Controllers/PermissionChangeHistoryController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

// Solo lectura: hoy ningún flujo del sistema escribe PermissionChangeHistory (tabla no
// alimentada por RolePermissionsController/PermissionsController). Se deja como catálogo
// de solo consulta, sin mutación vía API, para el día que se cablee esa escritura.
[ApiController, Route("api/permission-change-history"), Authorize(Roles = "Administrador,R_DITIC")]
public class PermissionChangeHistoryController : ControllerBase
{
    private readonly ICrudService<PermissionChangeHistory, CreatePermissionChangeHistoryDto, UpdatePermissionChangeHistoryDto> _svc;
    public PermissionChangeHistoryController(ICrudService<PermissionChangeHistory, CreatePermissionChangeHistoryDto, UpdatePermissionChangeHistoryDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
