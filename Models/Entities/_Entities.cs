namespace WsSeguUta.AuthSystem.API.Models.Entities;

public class User { public Guid Id { get; set; } public string Email { get; set; } = string.Empty; public string? DisplayName { get; set; } public Guid? AzureObjectId { get; set; } public bool IsActive { get; set; } = true; public DateTime CreatedAt { get; set; } = DateTime.UtcNow; public DateTime? LastLogin { get; set; } public string UserType { get; set; } = "AzureAD"; }
public class UserEmployee { public int Id { get; set; } public Guid UserId { get; set; } public string EmployeeEmail { get; set; } = string.Empty; public bool IsActive { get; set; } = true; public DateTime? SyncDate { get; set; } public string? Notes { get; set; } }
public class AppParam { public string Nemonic { get; set; } = string.Empty; public string Value { get; set; } = string.Empty; public string DataType { get; set; } = "string"; public string Category { get; set; } = "General"; public string? Description { get; set; } public bool IsEncrypted { get; set; } = false; public DateTime LastModified { get; set; } = DateTime.UtcNow; public string? ModifiedBy { get; set; } }
public class LocalUserCredential { public Guid UserId { get; set; } public string PasswordHash { get; set; } = string.Empty; public DateTime PasswordCreatedAt { get; set; } = DateTime.UtcNow; public DateTime? PasswordExpiresAt { get; set; } public bool MustChangePassword { get; set; } = false; public int FailedAttempts { get; set; } = 0; public DateTime? LastFailedAttempt { get; set; } public DateTime? LockedUntil { get; set; } public bool IsLocked { get; set; } = false; public bool TwoFactorEnabled { get; set; } = false; public string? TwoFactorSecret { get; set; } public string? SecurityQuestions { get; set; } }
public class SecurityToken { public Guid Id { get; set; } = Guid.NewGuid(); public Guid UserId { get; set; } public string TokenType { get; set; } = "PasswordReset"; public string TokenHash { get; set; } = string.Empty; public DateTime ExpiresAt { get; set; } public bool IsUsed { get; set; } = false; public DateTime CreatedAt { get; set; } = DateTime.UtcNow; public string? AdditionalData { get; set; } }
public class PasswordHistory { public long Id { get; set; } public Guid UserId { get; set; } public string PasswordHash { get; set; } = string.Empty; public DateTime CreatedAt { get; set; } = DateTime.UtcNow; }
public class UserAccountLock { public long Id { get; set; } public Guid UserId { get; set; } public string LockType { get; set; } = "FailedAttempts"; public string LockReason { get; set; } = string.Empty; public DateTime LockedAt { get; set; } = DateTime.UtcNow; public string? LockedBy { get; set; } public DateTime? AutoUnlockAt { get; set; } public DateTime? UnlockedAt { get; set; } public string? UnlockedBy { get; set; } public bool IsActive { get; set; } = true; }
public class Role { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string? Description { get; set; } public bool IsActive { get; set; } = true; public int Priority { get; set; } = 100; public DateTime CreatedAt { get; set; } = DateTime.UtcNow; public bool IsDeleted { get; set; } = false; }
public class Permission { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string Module { get; set; } = string.Empty; public string Action { get; set; } = "Read"; public string? Description { get; set; } public int Version { get; set; } = 1; public bool IsDeleted { get; set; } = false; }
public class RolePermission { public int RoleId { get; set; } public int PermissionId { get; set; } public DateTime GrantedAt { get; set; } = DateTime.UtcNow; public string? GrantedBy { get; set; } }
public class UserRole { public Guid UserId { get; set; } public int RoleId { get; set; } public DateTime AssignedAt { get; set; } = DateTime.UtcNow; public DateTime? ExpiresAt { get; set; } public string? AssignedBy { get; set; } public string? Reason { get; set; } public bool IsDeleted { get; set; } = false; }
public class MenuItem { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string? Url { get; set; } public string? Icon { get; set; } public int? ParentId { get; set; } public int Order { get; set; } = 0; public bool IsVisible { get; set; } = true; public string? ModuleName { get; set; } public bool IsDeleted { get; set; } = false; }
public class RoleMenuItem { public int RoleId { get; set; } public int MenuItemId { get; set; } public bool IsVisible { get; set; } = true; }
public class UserSession { public Guid SessionId { get; set; } = Guid.NewGuid(); public Guid UserId { get; set; } public string AccessToken { get; set; } = string.Empty; public string RefreshToken { get; set; } = string.Empty; public DateTime ExpiresAt { get; set; } public bool IsActive { get; set; } = true; public string? DeviceInfo { get; set; } public string? IpAddress { get; set; } public DateTime CreatedAt { get; set; } = DateTime.UtcNow; public string Status { get; set; } = "Active"; }
public class FailedLoginAttempt { public long Id { get; set; } public string UserEmail { get; set; } = string.Empty; public DateTime AttemptedAt { get; set; } = DateTime.UtcNow; public string? IpAddress { get; set; } public string? UserAgent { get; set; } public string? Reason { get; set; } public DateTime? WindowBucket { get; set; } }
public class AuditLog { public long Id { get; set; } public Guid? UserId { get; set; } public string Action { get; set; } = string.Empty; public string Module { get; set; } = string.Empty; public string? EntityId { get; set; } public string? OldValues { get; set; } public string? NewValues { get; set; } public string? IpAddress { get; set; } public string? UserAgent { get; set; } public DateTime Timestamp { get; set; } = DateTime.UtcNow; }
public class LoginHistory { public long Id { get; set; } public Guid? UserId { get; set; } public DateTime LoginDateTime { get; set; } = DateTime.UtcNow; public string LoginType { get; set; } = "Local"; public string? IpAddress { get; set; } public string? UserAgent { get; set; } public string? DeviceInfo { get; set; } public string? LocationInfo { get; set; } public string LoginStatus { get; set; } = "Success"; public string? FailureReason { get; set; } public Guid? SessionId { get; set; } }
public class UserActivityLog { public long Id { get; set; } public Guid UserId { get; set; } public Guid? SessionId { get; set; } public string Activity { get; set; } = string.Empty; public string? ActivityDetails { get; set; } public string? IpAddress { get; set; } public string? UserAgent { get; set; } public DateTime Timestamp { get; set; } = DateTime.UtcNow; public string? ModuleAccessed { get; set; } public string? ActionPerformed { get; set; } }
public class RoleChangeHistory { public long Id { get; set; } public Guid UserId { get; set; } public int RoleId { get; set; } public string ChangeType { get; set; } = "Assigned"; public string ChangedBy { get; set; } = string.Empty; public string? ChangeReason { get; set; } public string? PreviousValue { get; set; } public string? NewValue { get; set; } public DateTime? EffectiveFrom { get; set; } public DateTime? EffectiveTo { get; set; } public DateTime ChangeDateTime { get; set; } = DateTime.UtcNow; public bool ApprovalRequired { get; set; } = false; public string? ApprovedBy { get; set; } public DateTime? ApprovalDateTime { get; set; } }
public class PermissionChangeHistory { public long Id { get; set; } public int RoleId { get; set; } public int PermissionId { get; set; } public string ChangeType { get; set; } = "Added"; public string ChangedBy { get; set; } = string.Empty; public string? ChangeReason { get; set; } public DateTime ChangeDateTime { get; set; } = DateTime.UtcNow; public int AffectedUsersCount { get; set; } = 0; }
public class AzureSyncLog { public long Id { get; set; } public DateTime SyncDate { get; set; } = DateTime.UtcNow; public int RecordsProcessed { get; set; } = 0; public int NewUsers { get; set; } = 0; public int UpdatedUsers { get; set; } = 0; public int Errors { get; set; } = 0; public string? Details { get; set; } public string SyncType { get; set; } = "Auto"; }
public class HRSyncLog { public long Id { get; set; } public DateTime SyncDate { get; set; } = DateTime.UtcNow; public int RecordsProcessed { get; set; } = 0; public int NewUsers { get; set; } = 0; public int UpdatedUsers { get; set; } = 0; public int Errors { get; set; } = 0; public string? Details { get; set; } public string SyncType { get; set; } = "Auto"; }


// ========== NUEVAS ENTIDADES PARA CENTRALIZADOR DE AUTENTICACIÓN ==========

public class Application 
{ 
    public Guid Id { get; set; } = Guid.NewGuid(); 
    public string Name { get; set; } = string.Empty; 
    public string ClientId { get; set; } = string.Empty; 
    public string ClientSecretHash { get; set; } = string.Empty; 
    public string? Description { get; set; } 
    public bool IsActive { get; set; } = true; 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
    public string? CreatedBy { get; set; } 
    public DateTime? ModifiedAt { get; set; } = DateTime.UtcNow; 
    public string? ModifiedBy { get; set; } 
    public bool IsDeleted { get; set; } = false; 
}

public class LegacyAuthLog 
{ 
    public long Id { get; set; } 
    public Guid ApplicationId { get; set; } 
    public Guid? UserId { get; set; } 
    public string UserEmail { get; set; } = string.Empty; 
    public string AuthResult { get; set; } = string.Empty; 
    public string AuthType { get; set; } = string.Empty; // "Local", "Office365", "Legacy"
    public string? FailureReason { get; set; } 
    public string? IpAddress { get; set; } 
    public string? UserAgent { get; set; } 
    public int? ResponseTime { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
}

// ========== ENTIDADES OPTIMIZADAS PARA NOTIFICACIONES ==========

public class NotificationSubscription 
{ 
    public Guid Id { get; set; } = Guid.NewGuid(); 
    public Guid ApplicationId { get; set; } 
    public string EventType { get; set; } = string.Empty; // "Login", "Logout", "UserCreated", etc.
    public string WebhookUrl { get; set; } = string.Empty; 
    public string? SecretKey { get; set; } // Para validar la autenticidad del webhook con HMAC
    public bool IsActive { get; set; } = true; 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
    public string? CreatedBy { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public string? ModifiedBy { get; set; }
}

public class NotificationLog 
{ 
    public long Id { get; set; } 
    public Guid SubscriptionId { get; set; } 
    public string EventType { get; set; } = string.Empty; 
    public Guid? UserId { get; set; } 
    public string WebhookUrl { get; set; } = string.Empty; 
    public int? HttpStatusCode { get; set; } 
    public string? ResponseBody { get; set; } 
    public int? ResponseTime { get; set; } // en milisegundos
    public bool IsSuccess { get; set; } = false; 
    public string? ErrorMessage { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow; 
}

public class OAuthState
{
    public string stateId { get; set; }
    public string? clientId { get; set; }
    public string timestamp { get; set; }
    public string source { get; set; }
}

