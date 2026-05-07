using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAppAuthService
    {
        Task<AppAuthResponse> AuthenticateApplicationAsync(string clientId, string clientSecret, string? ipAddress, string? userAgent);
        Task<LegacyAuthResponse> AuthenticateUserLegacyAsync(string clientId, string clientSecret, string userEmail, string password, bool includePermissions, string? ipAddress, string? userAgent);
        Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId);
        Task<object?> GetApplicationStatsAsync(string clientId);
    }
}
