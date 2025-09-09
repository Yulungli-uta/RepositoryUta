// Controllers/RoleMenuItemsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/role-menu-items"), Authorize]
public class RoleMenuItemsController : ControllerBase
{
    private readonly ICrudService<RoleMenuItem, CreateRoleMenuItemDto, UpdateRoleMenuItemDto> _svc;
    public RoleMenuItemsController(ICrudService<RoleMenuItem, CreateRoleMenuItemDto, UpdateRoleMenuItemDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{roleId:int}/{menuItemId:int}")]
    public async Task<IActionResult> Get(int roleId, int menuItemId)
        => (await _svc.GetAsync(roleId, menuItemId)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRoleMenuItemDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpDelete("{roleId:int}/{menuItemId:int}")]
    public async Task<IActionResult> Delete(int roleId, int menuItemId)
        => (await _svc.DeleteAsync(roleId, menuItemId)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
