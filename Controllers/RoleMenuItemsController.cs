// Controllers/RoleMenuItemsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/role-menu-items"), Authorize]
public class RoleMenuItemsController : ControllerBase
{
    private readonly ICrudService<RoleMenuItem, CreateRoleMenuItemDto, UpdateRoleMenuItemDto> _svc;
    private readonly IGenericRepository<RoleMenuItem> _repo;
    public RoleMenuItemsController(
        ICrudService<RoleMenuItem, CreateRoleMenuItemDto, UpdateRoleMenuItemDto> svc,
        IGenericRepository<RoleMenuItem> repo)
    {
        _svc = svc;
        _repo = repo;
    }

    /// <summary>Retorna TODAS las asignaciones de menú de un rol, sin límite de paginación.</summary>
    [HttpGet("role/{roleId:int}")]
    public async Task<IActionResult> GetByRole(int roleId, CancellationToken ct)
    {
        var items = await _repo.Query().Where(x => x.RoleId == roleId).ToListAsync(ct);
        return Ok(ApiResponse.Ok(items));
    }

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
