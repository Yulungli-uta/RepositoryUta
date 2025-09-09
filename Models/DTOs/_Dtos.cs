namespace WsSeguUta.AuthSystem.API.Models.DTOs;

public record ApiResponse(bool Success, object? Data, string? Message, IEnumerable<string>? Errors, DateTime Timestamp)
{ public static ApiResponse Ok(object? data=null, string? message=null) => new(true, data, message, null, DateTime.UtcNow);
  public static ApiResponse Fail(string message, IEnumerable<string>? errors=null) => new(false, null, message, errors, DateTime.UtcNow); }

public record LoginRequest(string Email, string Password);
public record RefreshRequest(string RefreshToken);
public record TokenPair(string AccessToken, string RefreshToken);

// Users
public record CreateUserDto(string Email, string? DisplayName, string UserType = "Local");
public record UpdateUserDto(string? DisplayName, bool? IsActive, Guid? AzureObjectId, string? UserType);

// UserEmployees
public record CreateUserEmployeeDto(Guid UserId, string EmployeeEmail, bool? IsActive, DateTime? SyncDate, string? Notes);
public record UpdateUserEmployeeDto(bool? IsActive, DateTime? SyncDate, string? Notes);

// AppParams
public record CreateAppParamDto(string Nemonic, string Value, string? DataType, string? Category, string? Description, bool? IsEncrypted, string? ModifiedBy);
public record UpdateAppParamDto(string? Value, string? DataType, string? Category, string? Description, bool? IsEncrypted, string? ModifiedBy);

// LocalUserCredentials
public record CreateLocalCredentialDto(Guid UserId, string PasswordHash, bool? MustChangePassword);
public record UpdateLocalCredentialDto(string? PasswordHash, bool? MustChangePassword, int? FailedAttempts, bool? IsLocked, DateTime? PasswordExpiresAt);

// SecurityTokens
public record CreateSecurityTokenDto(Guid UserId, string TokenType, string TokenHash, DateTime ExpiresAt, string? AdditionalData);
public record UpdateSecurityTokenDto(bool? IsUsed, DateTime? ExpiresAt, string? AdditionalData);

// PasswordHistory
public record CreatePasswordHistoryDto(Guid UserId, string PasswordHash);
public record UpdatePasswordHistoryDto(); // no-op

// UserAccountLocks
public record CreateUserAccountLockDto(Guid UserId, string LockType, string LockReason, DateTime? AutoUnlockAt, string? LockedBy);
public record UpdateUserAccountLockDto(bool? IsActive, DateTime? UnlockedAt, string? UnlockedBy);

// Roles
public record CreateRoleDto(string Name, string? Description, int Priority);
public record UpdateRoleDto(string? Description, bool? IsActive, int? Priority);

// Permissions
public record CreatePermissionDto(string Name, string Module, string Action, string? Description, int? Version);
public record UpdatePermissionDto(string? Description, bool? IsDeleted, int? Version);

// RolePermissions (link)
public record CreateRolePermissionDto(int RoleId, int PermissionId, string? GrantedBy);
public record UpdateRolePermissionDto(string? GrantedBy);

// UserRoles (link)
public record CreateUserRoleDto(Guid UserId, int RoleId, DateTime? ExpiresAt, string? AssignedBy, string? Reason);
public record UpdateUserRoleDto(DateTime? ExpiresAt, bool? IsDeleted, string? Reason);

// MenuItems
public record CreateMenuItemDto(int? ParentId, string Name, string? Url, string? Icon, int Order, string? ModuleName, bool? IsVisible);
public record UpdateMenuItemDto(int? ParentId, string? Name, string? Url, string? Icon, int? Order, string? ModuleName, bool? IsVisible);

// RoleMenuItems (link)
public record CreateRoleMenuItemDto(int RoleId, int MenuItemId, bool? IsVisible);
public record UpdateRoleMenuItemDto(bool? IsVisible);

// UserSessions
public record CreateUserSessionDto(Guid UserId, string AccessToken, string RefreshToken, DateTime ExpiresAt, bool? IsActive, string? DeviceInfo, string? IpAddress, string? Status);
public record UpdateUserSessionDto(bool? IsActive, DateTime? ExpiresAt, string? Status);

// FailedLoginAttempts
public record CreateFailedAttemptDto(string UserEmail, string? IpAddress, string? UserAgent, string? Reason, DateTime? WindowBucket);
public record UpdateFailedAttemptDto(string? Reason);

// AuditLog (normalmente solo lectura, pero dejamos DTO por si acaso)
public record CreateAuditLogDto(Guid? UserId, string Action, string Module, string? EntityId, string? OldValues, string? NewValues, string? IpAddress, string? UserAgent);
public record UpdateAuditLogDto(string? OldValues, string? NewValues);

// LoginHistory (solo lectura tÃ­pica)
public record CreateLoginHistoryDto(Guid? UserId, string LoginType, string LoginStatus, string? IpAddress, string? UserAgent, string? DeviceInfo, string? LocationInfo, Guid? SessionId);
public record UpdateLoginHistoryDto(string? LoginStatus, string? FailureReason);

// UserActivityLog
public record CreateUserActivityLogDto(Guid UserId, Guid? SessionId, string Activity, string? ActivityDetails, string? IpAddress, string? UserAgent, string? ModuleAccessed, string? ActionPerformed);
public record UpdateUserActivityLogDto(string? ActivityDetails);

// RoleChangeHistory
public record CreateRoleChangeHistoryDto(Guid UserId, int RoleId, string ChangeType, string ChangedBy, string? ChangeReason, string? PreviousValue, string? NewValue, DateTime? EffectiveFrom, DateTime? EffectiveTo, bool? ApprovalRequired, string? ApprovedBy, DateTime? ApprovalDateTime);
public record UpdateRoleChangeHistoryDto(string? ChangeReason, string? NewValue, DateTime? EffectiveTo, bool? ApprovalRequired, string? ApprovedBy, DateTime? ApprovalDateTime);

// PermissionChangeHistory
public record CreatePermissionChangeHistoryDto(int RoleId, int PermissionId, string ChangeType, string ChangedBy, string? ChangeReason, int? AffectedUsersCount);
public record UpdatePermissionChangeHistoryDto(string? ChangeReason, int? AffectedUsersCount);

// AzureSyncLog / HRSyncLog
public record CreateAzureSyncLogDto(DateTime? SyncDate, int? RecordsProcessed, int? NewUsers, int? UpdatedUsers, int? Errors, string? Details, string? SyncType);
public record UpdateAzureSyncLogDto(int? RecordsProcessed, int? NewUsers, int? UpdatedUsers, int? Errors, string? Details, string? SyncType);
public record CreateHRSyncLogDto(DateTime? SyncDate, int? RecordsProcessed, int? NewUsers, int? UpdatedUsers, int? Errors, string? Details, string? SyncType);
public record UpdateHRSyncLogDto(int? RecordsProcessed, int? NewUsers, int? UpdatedUsers, int? Errors, string? Details, string? SyncType);
