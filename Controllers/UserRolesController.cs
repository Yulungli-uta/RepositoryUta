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
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
    { 
        var pagedEntities = await _svc.ListAsync(page, pageSize, ct);
        return Ok(new
        {
            items = pagedEntities.Items,
            page = pagedEntities.Page,
            pageSize = pagedEntities.PageSize,
            totalCount = pagedEntities.TotalCount,
            totalPages = pagedEntities.TotalPages,
            hasPreviousPage = pagedEntities.HasPreviousPage,
            hasNextPage = pagedEntities.HasNextPage
        });
    }
    [HttpGet("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Get(Guid userId, int roleId)
        => (await _svc.GetAsync(userId, roleId)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRoleDto dto)
    {
        try
        {
            return Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(ApiResponse.Fail(ex.Message));
        }
    }

    [HttpPut("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Update(Guid userId, int roleId, [FromBody] UpdateUserRoleDto dto)
        => (await _svc.UpdateAsync(new object[] { userId, roleId }, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpDelete("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Delete(Guid userId, int roleId)
        => (await _svc.DeleteAsync(userId, roleId)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
