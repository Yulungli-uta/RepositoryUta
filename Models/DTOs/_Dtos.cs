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


// ========== NUEVOS DTOs PARA CENTRALIZADOR DE AUTENTICACIÓN ==========

// Applications
public record CreateApplicationDto(string Name, string ClientId, string ClientSecret, string? Description, int? TokenExpirationMin, int? RefreshTokenExpDays, string? AllowedOrigins);
public record UpdateApplicationDto(string? Name, string? Description, bool? IsActive, int? TokenExpirationMin, int? RefreshTokenExpDays, string? AllowedOrigins);

// Application Tokens
public record CreateApplicationTokenDto(Guid ApplicationId, string TokenHash, DateTime ExpiresAt, string? IpAddress, string? UserAgent);
public record UpdateApplicationTokenDto(bool? IsActive);

// Legacy Auth
public record LegacyAuthRequest(string ClientId, string ClientSecret, string UserEmail, string Password, bool? IncludePermissions);
public record LegacyAuthResponse(bool Success, string Message, Guid? UserId, string? Email, string? DisplayName, string? UserType, object? Roles, object? Permissions);

// Token Validation
public record ValidateTokenRequest(string Token, string? ClientId);
public record ValidateTokenResponse(bool IsValid, string TokenType, DateTime? ExpiresAt, Guid? UserId, Guid? SessionId, string? Message, string Email);

// Application Authentication
public record AppAuthRequest(string ClientId, string ClientSecret);
public record AppAuthResponse(bool Success, string Message, Guid? TokenId, DateTime? ExpiresAt, Guid? ApplicationId);

// Legacy Auth Log
public record CreateLegacyAuthLogDto(Guid ApplicationId, Guid? UserId, string UserEmail, string AuthResult, string? FailureReason, string? IpAddress, string? UserAgent, string? RequestData, int? ResponseTime);
public record UpdateLegacyAuthLogDto(); // no-op, logs are immutable


// ========== DTOs PARA NOTIFICACIONES DE OFFICE365 ==========

// Notification Subscriptions
public record CreateNotificationSubscriptionDto(Guid ApplicationId, string EventType, string WebhookUrl, string? SecretKey);
public record UpdateNotificationSubscriptionDto(string? WebhookUrl, string? SecretKey, bool? IsActive);

// Notification Events
public record CreateNotificationEventDto(Guid? UserId, Guid? ApplicationId, string EventType, object EventData);
public record NotificationEventDto(long Id, Guid? UserId, Guid? ApplicationId, string EventType, object EventData, DateTime CreatedAt, bool IsProcessed);

// Webhook Payloads
public record WebhookPayload(string EventType, DateTime Timestamp, object Data, string Signature);
public record LoginEventData(Guid UserId, string Email, string DisplayName, string LoginType, string IpAddress, DateTime LoginTime, object? Roles, object? Permissions, TokenPair? pair);
public record LogoutEventData(Guid UserId, string Email, DateTime LogoutTime);
public record UserCreatedEventData(Guid UserId, string Email, string DisplayName, string UserType, DateTime CreatedAt);

// Notification Management
public record NotificationStatsDto(int TotalSubscriptions, int ActiveSubscriptions, int TotalLogs, int SuccessfulLogs, int FailedNotifications);
public record SubscriptionStatsDto(Guid SubscriptionId, string EventType, string WebhookUrl, bool IsActive, int TotalNotifications, int SuccessfulNotifications, int FailedNotifications, DateTime? LastModified);


// ========== DTOs PARA AZURE AD MANAGEMENT ==========

// Crear usuario en Azure AD
public record CreateAzureUserDto(
    string Email,
    string DisplayName,
    string GivenName,
    string Surname,
    string Password,
    bool ForceChangePasswordNextSignIn = true,
    string? MailNickname = null,
    string? JobTitle = null,
    string? Department = null,
    string? OfficeLocation = null,
    string? MobilePhone = null,
    string? BusinessPhones = null,
    string? StreetAddress = null,
    string? City = null,
    string? State = null,
    string? Country = null,
    string? PostalCode = null,
    string? UsageLocation = null,
    string? EmployeeId = null,
    string? CompanyName = null,
    bool AccountEnabled = true
);

// Actualizar usuario en Azure AD
public record UpdateAzureUserDto(
    string? DisplayName = null,
    string? GivenName = null,
    string? Surname = null,
    string? JobTitle = null,
    string? Department = null,
    string? OfficeLocation = null,
    string? MobilePhone = null,
    string? BusinessPhones = null,
    string? StreetAddress = null,
    string? City = null,
    string? State = null,
    string? Country = null,
    string? PostalCode = null,
    string? UsageLocation = null,
    string? EmployeeId = null,
    string? CompanyName = null,
    bool? AccountEnabled = null
);

// Usuario de Azure AD (respuesta)
public record AzureUserDto(
    string Id,
    string Email,
    string DisplayName,
    string? GivenName,
    string? Surname,
    string? JobTitle,
    string? Department,
    string? OfficeLocation,
    string? MobilePhone,
    List<string>? BusinessPhones,
    string? StreetAddress,
    string? City,
    string? State,
    string? Country,
    string? PostalCode,
    string? UsageLocation,
    string? EmployeeId,
    string? CompanyName,
    bool AccountEnabled,
    DateTime? CreatedDateTime,
    DateTime? LastPasswordChangeDateTime,
    string? UserType,
    List<string>? AssignedLicenses
);

// Cambiar contraseña
public record ChangePasswordDto(
    string NewPassword,
    bool ForceChangeNextSignIn = false
);

// Resultado de validación de contraseña
public record PasswordValidationResult(
    bool IsValid,
    List<string> Errors,
    int StrengthScore,
    string StrengthLevel
);

// Respuesta de reset de contraseña
public record PasswordResetResponse(
    bool Success,
    string? TemporaryPassword,
    DateTime ExpiresAt,
    string Message
);

// Rol de Azure AD
public record AzureRoleDto(
    string Id,
    string DisplayName,
    string? Description,
    bool IsBuiltIn,
    string? RoleTemplateId,
    List<string>? RolePermissions
);

// Asignar rol
public record AssignRoleDto(
    string RoleId,
    string UserId,
    string? Justification = null
);

// Crear grupo en Azure AD
public record CreateAzureGroupDto(
    string DisplayName,
    string? Description = null,
    string? MailNickname = null,
    string GroupType = "Security",
    bool MailEnabled = false,
    bool SecurityEnabled = true,
    List<string>? Owners = null,
    List<string>? Members = null
);

// Actualizar grupo en Azure AD
public record UpdateAzureGroupDto(
    string? DisplayName = null,
    string? Description = null,
    string? MailNickname = null
);

// Grupo de Azure AD (respuesta)
public record AzureGroupDto(
    string Id,
    string DisplayName,
    string? Description,
    string? Mail,
    string? MailNickname,
    bool MailEnabled,
    bool SecurityEnabled,
    string GroupType,
    DateTime? CreatedDateTime,
    int MemberCount,
    List<string>? GroupTypes
);

// Resultado de operación masiva
public record BulkOperationResult(
    int TotalRequested,
    int Successful,
    int Failed,
    List<BulkOperationError> Errors,
    TimeSpan Duration
);

public record BulkOperationError(
    string Identifier,
    string ErrorMessage,
    string ErrorCode
);

// Resultado de sincronización
public record SyncResult(
    bool Success,
    int UsersProcessed,
    int UsersCreated,
    int UsersUpdated,
    int UsersFailed,
    int GroupsProcessed,
    int GroupsCreated,
    int GroupsUpdated,
    List<string> Errors,
    DateTime SyncDateTime,
    TimeSpan Duration
);

// Resultado paginado
public record PagedResult<T>(
    List<T> Items,
    int CurrentPage,
    int PageSize,
    int TotalItems,
    int TotalPages,
    bool HasNextPage,
    bool HasPreviousPage
);
