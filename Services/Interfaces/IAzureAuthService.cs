using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAzureAuthService
    {
        Task<(string Url, string State)> BuildAuthUrlAsync(string? clientId = null, string? browserId = null);
        Task<TokenPair?> HandleCallbackAsync(string code, string state, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null);
    }
}
