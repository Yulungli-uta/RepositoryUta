using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
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
}
