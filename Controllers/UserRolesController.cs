// Controllers/UserRolesController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/user-roles"), Authorize]
public class UserRolesController : ControllerBase
{
    private readonly ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> _svc;
    public UserRolesController(ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{userId:guid}/{roleId:int}/{assignedAt}")]
    public async Task<IActionResult> Get(Guid userId, int roleId, DateTime assignedAt)
        => (await _svc.GetAsync(userId, roleId, assignedAt)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRoleDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));

    [HttpPut]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateUserRoleDto dto)        
        => (await _svc.UpdateAsync(id, dto)) is { } e? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpDelete("{userId:guid}/{roleId:int}/{assignedAt}")]
    public async Task<IActionResult> Delete(Guid userId, int roleId, DateTime assignedAt)
        => (await _svc.DeleteAsync(userId, roleId, assignedAt)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
