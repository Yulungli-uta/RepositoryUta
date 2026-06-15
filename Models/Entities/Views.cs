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
/// Mapea auth.vw_ActiveSessions — sesiones de usuario activas con conexión WS
/// </summary>
public class VwActiveSession
{
    public Guid SessionId { get; set; }
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string UserType { get; set; } = string.Empty;
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? BrowserId { get; set; }
    public DateTime LoginAt { get; set; }
    public DateTime? LastActivityAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? WsConnectionId { get; set; }
    public DateTime? WsLastPing { get; set; }
    public bool? WsIsActive { get; set; }
}

/// <summary>
/// Mapea auth.vw_ActiveApiClients — clientes API con estadísticas de uso
/// </summary>
public class VwActiveApiClient
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? CreatedBy { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public DateTime? SecretRotatedAt { get; set; }
    public string? SecretRotatedBy { get; set; }
    public DateTime? SuspendedAt { get; set; }
    public string? SuspendedBy { get; set; }
    public int CallsLast24h { get; set; }
    public string? LastIpAddress { get; set; }
    public string? LastUserAgent { get; set; }
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
