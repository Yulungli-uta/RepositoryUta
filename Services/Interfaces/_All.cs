using System.Linq.Expressions;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
  public interface IAuthService { 
        Task<TokenPair?> LoginLocalAsync(string email,string password, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null); 
        Task<TokenPair?> RefreshAsync(string refreshToken); 
        Task<bool> LogoutAsync(string refreshToken); 
        Task<object?> MeAsync(Guid userId); 
        Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId); 
        Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword); 
    }
  public interface ITokenService 
    { 
        string Create(Guid userId,string email,IEnumerable<string> roles); string Hash(string input); 
    }
  public interface IAzureAuthService 
    { 
        Task<(string Url,string State)> BuildAuthUrlAsync(string? clientId = null, string? browserId = null); 
        Task<TokenPair?> HandleCallbackAsync(string code,string state, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null); 
    }
  public interface IMenuService { Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId); }
  
  // ========== NUEVAS INTERFACES PARA CENTRALIZADOR ==========
  public interface IAppAuthService 
  { 
    Task<AppAuthResponse> AuthenticateApplicationAsync(string clientId, string clientSecret, string? ipAddress, string? userAgent);
    Task<LegacyAuthResponse> AuthenticateUserLegacyAsync(string clientId, string clientSecret, string userEmail, string password, bool includePermissions, string? ipAddress, string? userAgent);
    Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId);
    Task<object?> GetApplicationStatsAsync(string clientId);
  }
  
  // ========== INTERFAZ PARA NOTIFICACIONES ==========
  public interface INotificationService 
  { 
    Task<Guid> CreateSubscriptionAsync(Guid applicationId, string eventType, string webhookUrl, string? secretKey);
    Task<bool> UpdateSubscriptionAsync(Guid subscriptionId, string? webhookUrl, string? secretKey, bool? isActive);
    Task<bool> DeleteSubscriptionAsync(Guid subscriptionId);
    Task<IEnumerable<NotificationSubscription>> GetSubscriptionsByApplicationAsync(Guid applicationId);
    Task NotifyLoginEventAsync(Guid userId, string loginType, string? ipAddress, object? roles, object? permissions, TokenPair? pair, string browserId);
    Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair, string browserId);
    Task NotifyLogoutEventAsync(Guid userId);
    Task NotifyUserCreatedEventAsync(Guid userId);
    Task<NotificationStatsDto> GetNotificationStatsAsync();
    Task<IEnumerable<SubscriptionStatsDto>> GetSubscriptionStatsAsync(Guid applicationId);
    Task ProcessPendingNotificationsAsync();
  }

  // ========== INTERFAZ PARA WEBSOCKETS ==========
  public interface IWebSocketConnectionService
  {
    Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null);
    Task UnregisterConnectionAsync(string connectionId);
    Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId);
    Task<bool> IsConnectionActiveAsync(string connectionId);
    Task UpdateLastPingAsync(string connectionId);
    Task<int> GetActiveConnectionCountAsync(string clientId);
    Task CleanupInactiveConnectionsAsync(int inactiveMinutes = 60);
  }

  // CRUD genérico para todas las entidades
  public interface ICrudService<TEntity, TCreate, TUpdate> where TEntity: class
  {
    Task<IEnumerable<TEntity>> ListAsync(int page,int size);
    Task<TEntity?> GetAsync(params object[] key);
    Task<TEntity> CreateAsync(TCreate dto);
    Task<TEntity?> UpdateAsync(object key, TUpdate dto);
    Task<bool> DeleteAsync(params object[] key);
  }

  // ========== INTERFAZ PARA AZURE AD MANAGEMENT ==========
  public interface IAzureManagementService
  {
    // Gestión de Usuarios en Azure AD
    Task<AzureUserDto> CreateUserInAzureAsync(CreateAzureUserDto dto);
    Task<AzureUserDto?> GetUserFromAzureAsync(string azureObjectId);
    Task<AzureUserDto?> GetUserByEmailFromAzureAsync(string email);
    Task<AzureUserDto?> UpdateUserInAzureAsync(string azureObjectId, UpdateAzureUserDto dto);
    Task<bool> EnableDisableUserInAzureAsync(string azureObjectId, bool enable);
    Task<bool> DeleteUserFromAzureAsync(string azureObjectId, bool permanentDelete = false);
    Task<PagedResult<AzureUserDto>> ListUsersFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null);
    
    // Gestión de Contraseñas
    Task<string> ResetPasswordInAzureAsync(string azureObjectId, bool forceChange = true);
    Task<bool> ChangePasswordInAzureAsync(string azureObjectId, string newPassword, bool forceChangeNextSignIn = false);
    Task<PasswordValidationResult> ValidatePasswordPolicyAsync(string password);
    Task<string> GenerateSecurePasswordAsync();
    
    // Gestión de Roles de Directorio de Azure AD
    Task<IEnumerable<AzureRoleDto>> GetAllAzureDirectoryRolesAsync();
    Task<IEnumerable<AzureRoleDto>> GetUserAzureRolesAsync(string azureObjectId);
    Task<bool> AssignAzureRoleAsync(string azureObjectId, string roleId);
    Task<bool> RemoveAzureRoleAsync(string azureObjectId, string roleId);
    Task<IEnumerable<AzureUserDto>> GetRoleMembersAsync(string roleId);
    
    // Gestión de Grupos de Azure AD
    Task<AzureGroupDto> CreateGroupInAzureAsync(CreateAzureGroupDto dto);
    Task<AzureGroupDto?> GetGroupFromAzureAsync(string groupId);
    Task<AzureGroupDto?> UpdateGroupInAzureAsync(string groupId, UpdateAzureGroupDto dto);
    Task<bool> DeleteGroupFromAzureAsync(string groupId);
    Task<PagedResult<AzureGroupDto>> ListGroupsFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null);
    Task<bool> AddUserToAzureGroupAsync(string groupId, string azureObjectId);
    Task<bool> RemoveUserFromAzureGroupAsync(string groupId, string azureObjectId);
    Task<IEnumerable<AzureUserDto>> GetGroupMembersAsync(string groupId);
    Task<IEnumerable<AzureGroupDto>> GetUserAzureGroupsAsync(string azureObjectId);
    
    // Operaciones Masivas
    Task<BulkOperationResult> BulkCreateUsersAsync(IEnumerable<CreateAzureUserDto> users);
    Task<BulkOperationResult> BulkAddUsersToGroupAsync(string groupId, IEnumerable<string> userIds);
    
    // Sincronización
    Task<SyncResult> SyncUserToLocalDbAsync(string azureObjectId);
  }
}

