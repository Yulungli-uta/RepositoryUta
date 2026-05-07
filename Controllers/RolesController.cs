using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

    public RolesController(ICrudService<Role, CreateRoleDto, UpdateRoleDto> svc)
    {
        _svc = svc;
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
        return Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateRoleDto dto)
    {
        var entity = await _svc.UpdateAsync(id, dto);
        return entity is not null
            ? Ok(ApiResponse.Ok(entity))
            : NotFound(ApiResponse.Fail("No existe"));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var deleted = await _svc.DeleteAsync(id);
        return deleted
            ? Ok(ApiResponse.Ok(message: "Eliminado"))
            : NotFound(ApiResponse.Fail("No existe"));
    }
}