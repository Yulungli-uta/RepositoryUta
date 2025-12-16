using System.ComponentModel.DataAnnotations.Schema;

namespace WsSeguUta.AuthSystem.API.Models.Entities;

/// <summary>
/// Entidad que mapea la vista vw_UserRoles
/// </summary>
[Table("vw_UserRoles", Schema = "dbo")]
public class VwUserRole
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
/// Entidad que mapea la vista vw_RoleMenuItems
/// </summary>
[Table("vw_RoleMenuItems", Schema = "dbo")]
public class VwRoleMenuItem
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
