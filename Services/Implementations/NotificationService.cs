using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Hubs;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class NotificationService : INotificationService
    {
        private readonly AuthDbContext _context;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<NotificationService> _logger;
        private readonly IHubContext<NotificationHub>? _hubContext;

        public NotificationService(
            AuthDbContext context,
            IHttpClientFactory httpClientFactory,
            ILogger<NotificationService> logger,
            IHubContext<NotificationHub>? hubContext = null)
        {
            _context = context;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _hubContext = hubContext;
        }

        public async Task<Guid> CreateSubscriptionAsync(Guid applicationId, string eventType, string webhookUrl, string? secretKey)
        {
            var appExists = await _context.Applications.AnyAsync(a => a.Id == applicationId && a.IsActive && !a.IsDeleted);
            if (!appExists)
                throw new ArgumentException("Application not found or inactive");

            var subscription = new NotificationSubscription
            {
                ApplicationId = applicationId,
                EventType = eventType,
                WebhookUrl = webhookUrl,
                SecretKey = secretKey
            };

            _context.NotificationSubscriptions.Add(subscription);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Suscripción creada: {SubscriptionId} para aplicación {ApplicationId}", subscription.Id, applicationId);
            return subscription.Id;
        }

        public async Task<bool> UpdateSubscriptionAsync(Guid subscriptionId, string? webhookUrl, string? secretKey, bool? isActive)
        {
            try
            {
                var subscription = await _context.NotificationSubscriptions.FindAsync(subscriptionId);
                if (subscription == null) return false;

                if (!string.IsNullOrEmpty(webhookUrl)) subscription.WebhookUrl = webhookUrl;
                if (secretKey != null) subscription.SecretKey = secretKey;
                if (isActive.HasValue) subscription.IsActive = isActive.Value;

                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error actualizando suscripción {SubscriptionId}", subscriptionId);
                return false;
            }
        }

        public async Task<bool> DeleteSubscriptionAsync(Guid subscriptionId)
        {
            try
            {
                var subscription = await _context.NotificationSubscriptions.FindAsync(subscriptionId);
                if (subscription == null) return false;

                _context.NotificationSubscriptions.Remove(subscription);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error eliminando suscripción {SubscriptionId}", subscriptionId);
                return false;
            }
        }

        public async Task<IEnumerable<NotificationSubscription>> GetSubscriptionsByApplicationAsync(Guid applicationId)
        {
            return await _context.NotificationSubscriptions
                .Where(s => s.ApplicationId == applicationId && s.IsActive)
                .ToListAsync();
        }

        public async Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair, string browserId)
        {
            try
            {
                var application = await _context.Applications
                    .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (application == null)
                {
                    _logger.LogWarning("Aplicación con clientId {ClientId} no encontrada", clientId);
                    return;
                }

                var subscriptions = await _context.NotificationSubscriptions
                    .Where(s => s.ApplicationId == application.Id && s.EventType == "Login" && s.IsActive)
                    .ToListAsync();

                if (!subscriptions.Any())
                    return;

                var eventData = await PrepareLoginEventData(userId, loginType, ipAddress, clientId, pair);
                if (eventData == null) return;

                foreach (var subscription in subscriptions)
                {
                    switch (subscription.NotificationType?.ToLower())
                    {
                        case "webhook":
                            await SendWebhookNotificationAsync(subscription, eventData);
                            break;
                        case "websocket":
                            await SendWebSocketNotificationAsync(subscription, eventData, clientId, browserId);
                            break;
                        case "both":
                        default:
                            await SendWebhookNotificationAsync(subscription, eventData);
                            await SendWebSocketNotificationAsync(subscription, eventData, clientId, browserId);
                            break;
                    }
                }

                _logger.LogInformation("Notificaciones enviadas para usuario {UserId} a aplicación {ClientId}", userId, clientId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar notificaciones a {ClientId}", clientId);
            }
        }

        public async Task NotifyLoginEventAsync(Guid userId, string loginType, string? ipAddress, object? roles, object? permissions, TokenPair? pair, string browserId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new LoginEventData(userId, user.Email, user.DisplayName ?? "",
                    loginType, ipAddress ?? "", DateTime.Now, roles, permissions, pair: pair);

                await SendDirectNotificationsAsync("Login", eventData);
                _logger.LogInformation("Notificación de login enviada para usuario {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando notificación de login para usuario {UserId}", userId);
            }
        }

        public async Task NotifyLogoutEventAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new LogoutEventData(userId, user.Email, DateTime.Now);
                await SendDirectNotificationsAsync("Logout", eventData);
                _logger.LogInformation("Notificación de logout enviada para usuario {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando notificación de logout para usuario {UserId}", userId);
            }
        }

        public async Task NotifyUserCreatedEventAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new UserCreatedEventData(userId, user.Email, user.DisplayName ?? "", user.UserType, user.CreatedAt);
                await SendDirectNotificationsAsync("UserCreated", eventData);
                _logger.LogInformation("Notificación de usuario creado enviada para {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando notificación de usuario creado para {UserId}", userId);
            }
        }

        public async Task<NotificationStatsDto> GetNotificationStatsAsync()
        {
            var totalSubscriptions = await _context.NotificationSubscriptions.CountAsync();
            var activeSubscriptions = await _context.NotificationSubscriptions.CountAsync(s => s.IsActive);
            var totalLogs = await _context.NotificationLogs.CountAsync();
            var successfulLogs = await _context.NotificationLogs.CountAsync(l => l.IsSuccess);
            var failedLogs = await _context.NotificationLogs.CountAsync(l => !l.IsSuccess);

            return new NotificationStatsDto(totalSubscriptions, activeSubscriptions, totalLogs, successfulLogs, failedLogs);
        }

        public async Task<IEnumerable<SubscriptionStatsDto>> GetSubscriptionStatsAsync(Guid applicationId)
        {
            var subscriptions = await _context.NotificationSubscriptions
                .Where(s => s.ApplicationId == applicationId)
                .Select(s => new { s.Id, s.EventType, s.WebhookUrl, s.IsActive, s.ModifiedAt })
                .ToListAsync();

            var ids = subscriptions.Select(s => s.Id).ToList();

            var logCounts = await _context.NotificationLogs
                .Where(l => ids.Contains(l.SubscriptionId))
                .GroupBy(l => new { l.SubscriptionId, l.IsSuccess })
                .Select(g => new { g.Key.SubscriptionId, g.Key.IsSuccess, Count = g.Count() })
                .ToListAsync();

            var byId = logCounts
                .GroupBy(x => x.SubscriptionId)
                .ToDictionary(g => g.Key, g => (
                    Total: g.Sum(x => x.Count),
                    Success: g.Where(x => x.IsSuccess).Sum(x => x.Count),
                    Failed: g.Where(x => !x.IsSuccess).Sum(x => x.Count)));

            return subscriptions.Select(s =>
            {
                var c = byId.GetValueOrDefault(s.Id);
                return new SubscriptionStatsDto(s.Id, s.EventType, s.WebhookUrl, s.IsActive,
                    c.Total, c.Success, c.Failed, s.ModifiedAt);
            });
        }

        public Task ProcessPendingNotificationsAsync()
        {
            _logger.LogInformation("ProcessPendingNotificationsAsync: las notificaciones se envían directamente");
            return Task.CompletedTask;
        }

        private async Task<object?> PrepareLoginEventData(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return null;

                var roles = await GetUserRolesAsync(userId);
                var permissions = await GetUserPermissionsAsync(userId);

                return new
                {
                    eventType = "Login",
                    timestamp = DateTime.Now,
                    context = new
                    {
                        initiatingApplication = clientId,
                        loginSource = loginType,
                        sessionScope = "specific",
                        notificationType = "hybrid"
                    },
                    data = new
                    {
                        userId,
                        email = user.Email,
                        displayName = user.DisplayName,
                        loginType,
                        ipAddress,
                        roles,
                        permissions
                    },
                    pair
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error preparando datos de evento de login para usuario {UserId}", userId);
                return null;
            }
        }

        private async Task SendWebhookNotificationAsync(NotificationSubscription subscription, object eventData)
        {
            if (string.IsNullOrEmpty(subscription.WebhookUrl)) return;
            await SendWebhookAsync(subscription, eventData);
        }

        private async Task SendWebSocketNotificationAsync(NotificationSubscription subscription, object eventData, string clientId, string browserId)
        {
            var startTime = DateTime.Now;
            try
            {
                if (_hubContext != null)
                {
                    var group = string.IsNullOrEmpty(browserId) ? $"app_{clientId}" : $"browser_{browserId}";
                    await _hubContext.Clients.Group(group).SendAsync("LoginNotification", eventData);
                }

                _context.NotificationLogs.Add(new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = "Login",
                    WebhookUrl = string.IsNullOrEmpty(browserId) ? $"websocket://app_{clientId}" : $"websocket://browser_{browserId}",
                    HttpStatusCode = 200,
                    ResponseBody = "delivered",
                    IsSuccess = true,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds,
                    CreatedAt = DateTime.Now
                });
                await _context.SaveChangesAsync();

                _logger.LogInformation("Notificación WebSocket enviada a {ClientId}", clientId);
            }
            catch (Exception ex)
            {
                _context.NotificationLogs.Add(new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = "Login",
                    WebhookUrl = string.IsNullOrEmpty(browserId) ? $"websocket://app_{clientId}" : $"websocket://browser_{browserId}",
                    HttpStatusCode = 0,
                    IsSuccess = false,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds,
                    ErrorMessage = ex.Message,
                    CreatedAt = DateTime.Now
                });
                await _context.SaveChangesAsync();
                _logger.LogError(ex, "Error al enviar notificación WebSocket a {ClientId}", clientId);
            }
        }

        private async Task SendDirectNotificationsAsync(string eventType, object eventData)
        {
            try
            {
                var subscriptions = await _context.NotificationSubscriptions
                    .Where(s => s.EventType == eventType && s.IsActive)
                    .ToListAsync();

                foreach (var subscription in subscriptions)
                    await SendWebhookAsync(subscription, eventData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enviando notificaciones directas para evento {EventType}", eventType);
            }
        }

        private async Task SendWebhookAsync(NotificationSubscription subscription, object eventData)
        {
            var startTime = DateTime.Now;
            var httpClient = _httpClientFactory.CreateClient();

            try
            {
                var jsonPayload = System.Text.Json.JsonSerializer.Serialize(eventData);
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                httpClient.Timeout = TimeSpan.FromSeconds(30);
                if (!string.IsNullOrEmpty(subscription.SecretKey))
                    content.Headers.Add("X-Webhook-Signature", GenerateSignature(jsonPayload, subscription.SecretKey));

                var response = await httpClient.PostAsync(subscription.WebhookUrl, content);
                var responseBody = await response.Content.ReadAsStringAsync();

                _context.NotificationLogs.Add(new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = eventData.GetType().Name.Replace("EventData", ""),
                    WebhookUrl = subscription.WebhookUrl,
                    HttpStatusCode = (int)response.StatusCode,
                    ResponseBody = responseBody,
                    IsSuccess = response.IsSuccessStatusCode,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds,
                    ErrorMessage = response.IsSuccessStatusCode ? null : $"HTTP {response.StatusCode}: {responseBody}"
                });
                await _context.SaveChangesAsync();

                _logger.LogInformation("Webhook enviado a {WebhookUrl} con status {StatusCode}", subscription.WebhookUrl, response.StatusCode);
            }
            catch (Exception ex)
            {
                _context.NotificationLogs.Add(new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = eventData.GetType().Name.Replace("EventData", ""),
                    WebhookUrl = subscription.WebhookUrl,
                    HttpStatusCode = 0,
                    IsSuccess = false,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds,
                    ErrorMessage = ex.Message
                });
                await _context.SaveChangesAsync();
                _logger.LogError(ex, "Error enviando webhook a {WebhookUrl}", subscription.WebhookUrl);
            }
        }

        private async Task<IEnumerable<string>> GetUserRolesAsync(Guid userId)
        {
            return await _context.UserRoles
                .Where(ur => ur.UserId == userId && !ur.IsDeleted)
                .Join(_context.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name)
                .ToListAsync();
        }

        private async Task<IEnumerable<object>> GetUserPermissionsAsync(Guid userId)
        {
            return await _context.UserRoles
                .Where(ur => ur.UserId == userId && !ur.IsDeleted)
                .Join(_context.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (ur, rp) => rp)
                .Join(_context.Permissions, rp => rp.PermissionId, p => p.Id, (rp, p) => p)
                .Where(p => !p.IsDeleted)
                .Select(p => new { p.Id, p.Name, p.Module, p.Action, p.Description })
                .Distinct()
                .ToListAsync();
        }

        private static string GenerateSignature(string payload, string secretKey)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLower();
        }
    }
}
