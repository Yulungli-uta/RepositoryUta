// Controllers/UsersController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Services;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/users"), Authorize]
public class UsersController : ControllerBase
{
    private readonly ICrudService<User, CreateUserDto, UpdateUserDto> _svc;
    private readonly AuthDbContext _context;
    private readonly IUserPermissionService _permissionService;
    
    public UsersController(
        ICrudService<User, CreateUserDto, UpdateUserDto> svc, 
        AuthDbContext context,
        IUserPermissionService permissionService)
    {
        _svc = svc;
        _context = context;
        _permissionService = permissionService;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateUserDto dto)
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));

    /// <summary>
    /// Obtiene roles, permisos y menús asignados a un usuario
    /// </summary>
    /// <param name="userId">ID del usuario</param>
    /// <returns>Objeto con roles, permissions (URLs únicas) y menuItems</returns>
    [HttpGet("{userId:guid}/permissions")]
    public async Task<IActionResult> GetUserPermissions(Guid userId)
    {
        try
        {
            var permissions = await _permissionService.GetUserPermissionsAsync(userId);
            return Ok(ApiResponse.Ok(permissions, "Permisos obtenidos exitosamente"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting permissions for user {userId}: {ex.Message}");
            return StatusCode(500, ApiResponse.Fail($"Error obteniendo permisos: {ex.Message}"));
        }
    }
}
