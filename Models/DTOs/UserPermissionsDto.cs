namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>
/// DTO que contiene todos los permisos, roles y menús de un usuario
/// </summary>
public class UserPermissionsDto
{
    public List<UserRoleDto> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public List<MenuItemDto> MenuItems { get; set; } = new();
}

/// <summary>
/// DTO que representa un rol asignado a un usuario (vw_UserRoles)
/// </summary>
public class UserRoleDto
{
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string UserType { get; set; } = string.Empty;
    public int RoleId { get; set; }
    public string RoleName { get; set; } = string.Empty;
    public string? RoleDescription { get; set; }
    public DateTime? AssignedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string? AssignedBy { get; set; }
}

/// <summary>
/// DTO que representa un item de menú asignado a un usuario (vw_RoleMenuItems)
/// </summary>
public class MenuItemDto
{
    public int RoleId { get; set; }
    public string RoleName { get; set; } = string.Empty;
    public int MenuItemId { get; set; }
    public string MenuItemName { get; set; } = string.Empty;
    public string? Url { get; set; }
    public string? Icon { get; set; }
    public int? ParentId { get; set; }
    public int Order { get; set; }
    public bool IsVisible { get; set; }
    public bool RoleSpecificVisibility { get; set; }
}
