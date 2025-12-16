using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services;

public interface IUserPermissionService
{
    Task<UserPermissionsDto> GetUserPermissionsAsync(Guid userId);
    Task<List<UserRoleDto>> GetUserRolesAsync(Guid userId);
    Task<List<MenuItemDto>> GetUserMenuItemsAsync(Guid userId);
    Task<List<string>> GetUserPermissionsUrlsAsync(Guid userId);
}

public class UserPermissionService : IUserPermissionService
{
    private readonly IUserPermissionRepository _repository;

    public UserPermissionService(IUserPermissionRepository repository)
    {
        _repository = repository;
    }

    public async Task<UserPermissionsDto> GetUserPermissionsAsync(Guid userId)
    {
        // ❌ ANTES:
        // var rolesTask = _repository.GetUserRolesAsync(userId);
        // var menuItemsTask = _repository.GetUserMenuItemsAsync(userId);
        // await Task.WhenAll(rolesTask, menuItemsTask);
        // var roles = await rolesTask;
        // var menuItems = await menuItemsTask;

        // ✅ AHORA: todo secuencial para no romper el DbContext

        // 1) Roles
        var roles = await _repository.GetUserRolesAsync(userId);

        // 2) Menús
        var menuItems = await _repository.GetUserMenuItemsAsync(userId);

        // 3) Permisos (URLs) derivados del menú
        var permissions = menuItems
            .Where(mi => !string.IsNullOrWhiteSpace(mi.Url))
            .Select(mi => mi.Url!)
            .Distinct()
            .OrderBy(url => url)
            .ToList();

        return new UserPermissionsDto
        {
            Roles = roles,
            Permissions = permissions,
            MenuItems = menuItems
        };
    }

    public async Task<List<UserRoleDto>> GetUserRolesAsync(Guid userId)
    {
        return await _repository.GetUserRolesAsync(userId);
    }

    public async Task<List<MenuItemDto>> GetUserMenuItemsAsync(Guid userId)
    {
        return await _repository.GetUserMenuItemsAsync(userId);
    }

    public async Task<List<string>> GetUserPermissionsUrlsAsync(Guid userId)
    {
        var menuItems = await _repository.GetUserMenuItemsAsync(userId);

        var permissions = menuItems
            .Where(mi => !string.IsNullOrWhiteSpace(mi.Url))
            .Select(mi => mi.Url!)
            .Distinct()
            .OrderBy(url => url)
            .ToList();

        return permissions;
    }
}
