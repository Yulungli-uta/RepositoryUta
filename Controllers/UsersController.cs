// Controllers/UsersController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/users"), Authorize]
public class UsersController : ControllerBase
{
    private readonly ICrudService<User, CreateUserDto, UpdateUserDto> _svc;
    private readonly AuthDbContext _context;
    
    public UsersController(ICrudService<User, CreateUserDto, UpdateUserDto> svc, AuthDbContext context)
    {
        _svc = svc;
        _context = context;
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
            // 1. Verificar que el usuario existe
            var user = await _context.Users
                .Where(u => u.Id == userId)
                .Select(u => new { u.Id, u.DisplayName, u.Email })
                .FirstOrDefaultAsync();

            if (user == null)
            {
                return NotFound(ApiResponse.Fail("Usuario no encontrado"));
            }

            // 2. Obtener roles del usuario (con DISTINCT para evitar duplicados)
            var roles = await _context.UserRoles
                .Where(ur => ur.UserId == userId)
                .Select(ur => new
                {
                    roleId = ur.RoleId,
                    roleName = ur.RoleName
                })
                .Distinct()
                .ToListAsync();

            var roleIds = roles.Select(r => r.roleId).ToList();

            // 3. Obtener menús asignados a esos roles (con DISTINCT)
            var menuItems = await _context.RoleMenuItems
                .Where(rmi => roleIds.Contains(rmi.RoleId))
                .Select(rmi => new
                {
                    menuItemId = rmi.MenuItemId,
                    menuItemName = rmi.MenuItemName,
                    url = rmi.Url,
                    icon = rmi.Icon,
                    parentId = rmi.ParentId,
                    order = rmi.Order,
                    roleId = rmi.RoleId,
                    roleName = rmi.RoleName
                })
                .Distinct()
                .OrderBy(m => m.order)
                .ToListAsync();

            // 4. Extraer URLs únicas (solo menús con URL, con DISTINCT)
            var permissions = menuItems
                .Where(m => !string.IsNullOrEmpty(m.url))
                .Select(m => m.url)
                .Distinct()
                .ToList();

            // 5. Preparar respuesta
            var response = new
            {
                userId = user.Id,
                displayName = user.DisplayName,
                email = user.Email,
                roles = roles,
                permissions = permissions,
                menuItems = menuItems
            };

            Console.WriteLine($"Permissions loaded for user {userId}: {roles.Count} roles, {permissions.Count} permissions, {menuItems.Count} menu items");

            return Ok(ApiResponse.Ok(response, "Permisos obtenidos exitosamente"));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error getting permissions for user {userId}: {ex.Message}");
            return StatusCode(500, ApiResponse.Fail($"Error obteniendo permisos: {ex.Message}"));
        }
    }
}
