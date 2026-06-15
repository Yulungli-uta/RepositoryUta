using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/roles")]
[Authorize]
public class RolesController : ControllerBase
{
    private readonly ICrudService<Role, CreateRoleDto, UpdateRoleDto> _svc;
    private readonly IAuditService _audit;

    public RolesController(ICrudService<Role, CreateRoleDto, UpdateRoleDto> svc, IAuditService audit)
    {
        _svc   = svc;
        _audit = audit;
    }

    [AllowAnonymous]
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok("roles controller activo");
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var entity = await _svc.GetAsync(id);
        return entity is not null
            ? Ok(ApiResponse.Ok(entity))
            : NotFound(ApiResponse.Fail("No existe"));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRoleDto dto)
    {
        var result = await _svc.CreateAsync(dto);

        await _audit.LogAsync(
            action:    "RoleCreated",
            module:    "Roles",
            entityId:  result.Id.ToString(),
            newValues: JsonSerializer.Serialize(new { result.Name, result.Description, result.Priority }));

        return Ok(ApiResponse.Ok(result));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateRoleDto dto)
    {
        var before = await _svc.GetAsync(id);
        if (before is null) return NotFound(ApiResponse.Fail("No existe"));

        var updated = await _svc.UpdateAsync(id, dto);
        if (updated is null) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action:    "RoleUpdated",
            module:    "Roles",
            entityId:  id.ToString(),
            oldValues: JsonSerializer.Serialize(new { before.Name, before.Description, before.Priority, before.IsActive }),
            newValues: JsonSerializer.Serialize(new { updated.Name, updated.Description, updated.Priority, updated.IsActive }));

        return Ok(ApiResponse.Ok(updated));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var before = await _svc.GetAsync(id);
        if (before is null) return NotFound(ApiResponse.Fail("No existe"));

        var deleted = await _svc.DeleteAsync(id);
        if (!deleted) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action:    "RoleDeleted",
            module:    "Roles",
            entityId:  id.ToString(),
            oldValues: JsonSerializer.Serialize(new { before.Name, before.Description, before.IsActive }));

        return Ok(ApiResponse.Ok(message: "Eliminado"));
    }
}