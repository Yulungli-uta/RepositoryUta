using System.Text.Json;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class UserActivityService : IUserActivityService
    {
        private const string AuthModule = "AUTH";
        private const string ClientEventAction = "CLIENT_EVENT";

        private readonly AuthDbContext _context;
        private readonly ILogger<UserActivityService> _logger;
        private readonly IAppClock _clock;

        public UserActivityService(AuthDbContext context, ILogger<UserActivityService> logger, IAppClock clock)
        {
            _context = context;
            _logger = logger;
            _clock = clock;
        }

        public async Task LogAsync(Guid userId, string activity, object? details = null, Guid? sessionId = null,
            string? ipAddress = null, string? userAgent = null)
        {
            try
            {
                _context.UserActivityLogs.Add(new UserActivityLog
                {
                    UserId = userId,
                    SessionId = sessionId,
                    Activity = Truncate(activity, 100)!,
                    ActivityDetails = details is null ? null : JsonSerializer.Serialize(details),
                    IpAddress = Truncate(ipAddress, 64),
                    UserAgent = Truncate(userAgent, 400),
                    Timestamp = _clock.Now,
                    ModuleAccessed = AuthModule,
                    ActionPerformed = ClientEventAction
                });
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Una falla de bitácora nunca debe convertirse en un error para el usuario
                _logger.LogError(ex, "No se pudo registrar el evento {Activity} del usuario {UserId}", activity, userId);
            }
        }

        private static string? Truncate(string? value, int max) =>
            value is null || value.Length <= max ? value : value[..max];
    }
}
