using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services;

public interface IUserPermissionService
{
    Task<UserPermissionsDto> GetUserPermissionsAsync(string userId);
    Task<List<UserRoleDto>> GetUserRolesAsync(string userId);
    Task<List<MenuItemDto>> GetUserMenuItemsAsync(string userId);
    Task<List<string>> GetUserPermissionsUrlsAsync(string userId);
}

public class UserPermissionService : IUserPermissionService
{
    private readonly IUserPermissionRepository _repository;

    public UserPermissionService(IUserPermissionRepository repository)
    {
        _repository = repository;
    }

    public async Task<UserPermissionsDto> GetUserPermissionsAsync(string userId)
    {
        var rolesTask = _repository.GetUserRolesAsync(userId);
        var menuItemsTask = _repository.GetUserMenuItemsAsync(userId);

        await Task.WhenAll(rolesTask, menuItemsTask);

        var roles = await rolesTask;
        var menuItems = await menuItemsTask;

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

    public async Task<List<UserRoleDto>> GetUserRolesAsync(string userId)
    {
        return await _repository.GetUserRolesAsync(userId);
    }

    public async Task<List<MenuItemDto>> GetUserMenuItemsAsync(string userId)
    {
        return await _repository.GetUserMenuItemsAsync(userId);
    }

    public async Task<List<string>> GetUserPermissionsUrlsAsync(string userId)
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
