using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAzureAuthService
    {
        Task<(string Url, string State)> BuildAuthUrlAsync(string? clientId = null, string? browserId = null, string? codeChallenge = null, string? deviceInfo = null);
        Task<TokenPair?> HandleCallbackAsync(string code, string state, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null, string? reference = null);

        /// <summary>
        /// Completa el login de Azure (reutiliza <see cref="HandleCallbackAsync"/> sin modificarlo) y,
        /// si el intento incluyó codeChallenge (PKCE), emite un deliveryCode de un solo uso para
        /// entregar el par de tokens vía <see cref="ExchangeDeliveryCodeAsync"/> en vez de por WebSocket.
        /// Si no hay codeChallenge (cliente antiguo), DeliveryCode viene null y el llamador debe
        /// usar el Pair directamente (comportamiento de compatibilidad).
        /// </summary>
        Task<(TokenPair? Pair, string? DeliveryCode)> CompleteLoginAndIssueDeliveryCodeAsync(
            string code, string state, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null, string? reference = null);

        /// <summary>
        /// Reclamo del login pendiente: si el aviso de entrega no llegó a la pestaña (celular en segundo plano,
        /// conexión caída), la pestaña pregunta por su deliveryCode con su browserId y su codeChallenge. El código
        /// por sí solo no sirve: se canjea únicamente con el codeVerifier que solo esa pestaña conoce (PKCE).
        /// Retorna null si no hay nada pendiente (sin distinguir el motivo) o si el reclamo está deshabilitado
        /// (AzureAd:PendingClaimEnabled).
        /// </summary>
        string? ClaimPendingDelivery(string browserId, string codeChallenge);

        /// <summary>
        /// Deja constancia en el historial de acceso de un intento Azure que no terminó en sesión
        /// (FailureReason con el motivo interno y la referencia mostrada al usuario). Nunca lanza.
        /// </summary>
        Task RecordLoginFailureAsync(string reason, string? email, string? reference, string? ipAddress, string? userAgent, string? deviceInfo);

        /// <summary>
        /// Canjea un deliveryCode por el par de tokens real, validando que el codeVerifier
        /// corresponda al codeChallenge registrado (RFC 7636). Un solo uso: se retira de la
        /// caché al validarse. Retorna null si es inválido, expiró o ya fue consumido.
        /// </summary>
        Task<TokenPair?> ExchangeDeliveryCodeAsync(string deliveryCode, string codeVerifier);
    }
}
