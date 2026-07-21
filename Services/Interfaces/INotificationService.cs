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
        /// <param name="deliveryCode">
        /// Si viene informado (flujo PKCE), el par de tokens NO se incluye en el mensaje
        /// WebSocket ni en el payload de webhook: solo viaja esta referencia de un solo uso,
        /// canjeable en POST /api/auth/azure/exchange.
        /// </param>
        Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair, string browserId, string? deliveryCode = null);
        Task NotifyLogoutEventAsync(Guid userId);
        Task NotifyUserCreatedEventAsync(Guid userId);
        Task<NotificationStatsDto> GetNotificationStatsAsync();
        Task<IEnumerable<SubscriptionStatsDto>> GetSubscriptionStatsAsync(Guid applicationId);
        Task ProcessPendingNotificationsAsync();
    }
}
