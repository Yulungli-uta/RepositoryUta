using System.Linq.Expressions;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
  public interface IAuthService { Task<TokenPair?> LoginLocalAsync(string email,string password); Task<TokenPair?> RefreshAsync(string refreshToken); Task<bool> LogoutAsync(string refreshToken); Task<object?> MeAsync(Guid userId); Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId); }
  public interface ITokenService { string Create(Guid userId,string email,IEnumerable<string> roles); string Hash(string input); }
  public interface IAzureAuthService { Task<(string Url,string State)> BuildAuthUrlAsync(string? clientId = null); Task<TokenPair?> HandleCallbackAsync(string code,string state); }
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
    Task NotifyLoginEventAsync(Guid userId, string loginType, string? ipAddress, object? roles, object? permissions);
    Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId);
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
}

