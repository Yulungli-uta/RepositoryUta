// Controllers/MenuItemsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/menu-items"), Authorize(Roles = "Administrador,R_DITIC")]
public class MenuItemsController : ControllerBase
{
    private readonly ICrudService<MenuItem, CreateMenuItemDto, UpdateMenuItemDto> _svc;
    private readonly ILogger<MenuItemsController> _logger;
        public MenuItemsController(
        ICrudService<MenuItem, CreateMenuItemDto, UpdateMenuItemDto> svc,
        ILogger<MenuItemsController> logger)
    {
        _svc = svc;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken ct = default)
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
    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateMenuItemDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateMenuItemDto dto)
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
