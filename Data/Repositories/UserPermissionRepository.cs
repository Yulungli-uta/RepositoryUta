using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Data.Repositories;

public interface IUserPermissionRepository
{
    Task<List<UserRoleDto>> GetUserRolesAsync(Guid userId);
    Task<List<MenuItemDto>> GetUserMenuItemsAsync(Guid userId);
    Task<List<int>> GetUserRoleIdsAsync(Guid userId);
}

public class UserPermissionRepository : IUserPermissionRepository
{
    private readonly AuthDbContext _context;

    public UserPermissionRepository(AuthDbContext context)
    {
        _context = context;
    }

    public async Task<List<UserRoleDto>> GetUserRolesAsync(Guid userId)
    {
        var roles = await _context.VwUserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => new UserRoleDto
            {
                UserId = ur.UserId,
                Email = ur.Email,
                DisplayName = ur.DisplayName,
                UserType = ur.UserType,
                RoleId = ur.RoleId,
                RoleName = ur.RoleName,
                RoleDescription = ur.RoleDescription,
                AssignedAt = ur.AssignedAt,
                ExpiresAt = ur.ExpiresAt,
                AssignedBy = ur.AssignedBy
            })
            .ToListAsync();

        return roles;
    }

    public async Task<List<MenuItemDto>> GetUserMenuItemsAsync(Guid userId)
    {
        // 1) Primero traemos los RoleId del usuario
        var roleIds = await GetUserRoleIdsAsync(userId);

        if (!roleIds.Any())
            return new List<MenuItemDto>();

        // 2) Luego traemos los menús de esos roles
        var menuItems = await _context.VwRoleMenuItems
            .Where(rmi => roleIds.Contains(rmi.RoleId))
            .Select(rmi => new MenuItemDto
            {
                RoleId = rmi.RoleId,
                RoleName = rmi.RoleName,
                MenuItemId = rmi.MenuItemId,
                MenuItemName = rmi.MenuItemName,
                Url = rmi.Url,
                Icon = rmi.Icon,
                ParentId = rmi.ParentId,
                Order = rmi.Order,
                IsVisible = rmi.IsVisible,
                RoleSpecificVisibility = rmi.RoleSpecificVisibility
            })
            .ToListAsync();

        return menuItems;
    }

    public async Task<List<int>> GetUserRoleIdsAsync(Guid userId)
    {
        var roleIds = await _context.VwUserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.RoleId)
            .Distinct()
            .ToListAsync();

        return roleIds;
    }
}
