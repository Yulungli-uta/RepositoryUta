using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAuthService
    {
        Task<TokenPair?> LoginLocalAsync(string email, string password, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null, string? browserId = null);
        Task<TokenPair?> RefreshAsync(string refreshToken);
        Task<bool> LogoutAsync(string refreshToken);
        Task<object?> MeAsync(Guid userId);
        Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId);
        Task<ChangePasswordResponse> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword);

        /// <summary>
        /// Genera un OTP de 6 dígitos válido 10 minutos. Funciona para usuarios Local y AzureAD.
        /// Para usuarios Local también verifica que existan credenciales locales.
        /// </summary>
        Task<RequestPasswordChange2FAResponse> RequestPasswordChange2FAAsync(Guid userId, bool isDevelopment = false);

        /// <summary>Verifica el OTP y cambia la contraseña si el código y la contraseña actual son correctos (solo usuarios Local).</summary>
        Task<ChangePasswordResponse> ChangePasswordWith2FAAsync(Guid userId, string currentPassword, string newPassword, string otpCode);

        /// <summary>
        /// Verifica y consume el OTP de cambio de contraseña sin aplicar el cambio de contraseña.
        /// Usado por el controlador para bifurcar el flujo por tipo de usuario (Local vs AzureAD).
        /// </summary>
        Task<ChangePasswordResponse> VerifyAndConsumePasswordOtpAsync(Guid userId, string otpCode);
    }
}
