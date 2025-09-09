// Controllers/PermissionsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/permissions"), Authorize]
public class PermissionsController : ControllerBase
{
    private readonly ICrudService<Permission, CreatePermissionDto, UpdatePermissionDto> _svc;
    public PermissionsController(ICrudService<Permission, CreatePermissionDto, UpdatePermissionDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreatePermissionDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdatePermissionDto dto)
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
