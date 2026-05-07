using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAuthService
    {
        Task<TokenPair?> LoginLocalAsync(string email, string password, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null);
        Task<TokenPair?> RefreshAsync(string refreshToken);
        Task<bool> LogoutAsync(string refreshToken);
        Task<object?> MeAsync(Guid userId);
        Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId);
        Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);

        /// <summary>Genera un OTP de 6 dígitos válido 10 minutos y lo almacena hasheado en SecurityTokens.</summary>
        Task<RequestPasswordChange2FAResponse> RequestPasswordChange2FAAsync(Guid userId, bool isDevelopment = false);

        /// <summary>Verifica el OTP y cambia la contraseña si el código y la contraseña actual son correctos.</summary>
        Task<ChangePasswordResponse> ChangePasswordWith2FAAsync(Guid userId, string currentPassword, string newPassword, string otpCode);
    }
}
