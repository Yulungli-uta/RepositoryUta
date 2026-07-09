using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class AzureAuthService : IAzureAuthService
    {
        private readonly IConfidentialClientApplication _msal;
        private readonly IConfiguration _cfg;
        private readonly IHttpClientFactory _http;
        private readonly IUserRepository _users;
        private readonly ITokenService _tokens;
        private readonly IAuthRepository _auth;
        private readonly IMemoryCache _cache;
        private readonly INotificationService _notificationService;
        private readonly IClientApplicationService _clientApplicationService;
        private readonly IIdentityProviderResolver _identityResolver;
        private readonly ILogger<AzureAuthService> _logger;

        public AzureAuthService(
            IConfidentialClientApplication msal,
            IConfiguration cfg,
            IHttpClientFactory http,
            IUserRepository users,
            ITokenService tokens,
            IAuthRepository auth,
            IMemoryCache cache,
            INotificationService notificationService,
            IClientApplicationService clientApplicationService,
            IIdentityProviderResolver identityResolver,
            ILogger<AzureAuthService> logger)
        {
            _msal = msal;
            _cfg = cfg;
            _http = http;
            _users = users;
            _tokens = tokens;
            _auth = auth;
            _cache = cache;
            _notificationService = notificationService;
            _clientApplicationService = clientApplicationService;
            _identityResolver = identityResolver;
            _logger = logger;
        }

        private async Task ValidateClientApplicationAsync(string? clientId)
        {
            var isAllowed = await _clientApplicationService.IsClientApplicationAllowedAsync(clientId);
            if (!isAllowed)
                throw new UnauthorizedAccessException("Aplicación cliente no autorizada.");
        }

        public async Task<(string Url, string State)> BuildAuthUrlAsync(string? clientId = null, string? browserId = null)
        {
            await ValidateClientApplicationAsync(clientId);

            var normalizedClientId = clientId!.Trim();
            var stateGuid = Guid.NewGuid().ToString("N");

            var stateData = new
            {
                stateId = stateGuid,
                clientId = normalizedClientId,
                browserId,
                timestamp = DateTime.Now.ToString("O"),
                source = "azure_auth"
            };

            var stateJson = System.Text.Json.JsonSerializer.Serialize(stateData);
            var stateEncoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(stateJson));

            _cache.Set($"ms_state:{stateGuid}", stateData, TimeSpan.FromMinutes(10));

            var redirect = _cfg["AzureAd:RedirectUri"]!;
            var scopes = new[] { "openid", "profile", "email", "offline_access", "User.Read" };

            var url = await _msal.GetAuthorizationRequestUrl(scopes)
                .WithRedirectUri(redirect)
                .WithExtraQueryParameters(new Dictionary<string, string> { { "state", stateEncoded } })
                .ExecuteAsync();

            return (url.ToString(), stateEncoded);
        }

        public async Task<TokenPair?> HandleCallbackAsync(string code, string state, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null)
        {
            var stateJson = Encoding.UTF8.GetString(Convert.FromBase64String(state));
            var stateData = System.Text.Json.JsonDocument.Parse(stateJson).RootElement;

            var stateId = stateData.GetProperty("stateId").GetString();
            var cacheKey = $"ms_state:{stateId}";

            //_logger.LogInformation("******************HandleCallbackAsync - code: {code},  state: {state}", code, state);
            if (!_cache.TryGetValue(cacheKey, out _))
                throw new UnauthorizedAccessException("State inválido o expirado.");

            // Eliminar el state inmediatamente para evitar reutilización (anti-replay)
            _cache.Remove(cacheKey);

            var clientId = stateData.TryGetProperty("clientId", out var cProp) && cProp.ValueKind != System.Text.Json.JsonValueKind.Null
                ? cProp.GetString()
                : null;

            await ValidateClientApplicationAsync(clientId);

            var redirect = _cfg["AzureAd:RedirectUri"]!;
            var scopes = new[] { "openid", "profile", "email", "offline_access", "User.Read" };
            var result = await _msal.AcquireTokenByAuthorizationCode(scopes, code)
                .ExecuteAsync();

            var client = _http.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            var res = await client.GetAsync("https://graph.microsoft.com/v1.0/me");
            res.EnsureSuccessStatusCode();
            var json = await res.Content.ReadAsStringAsync();
            var doc = System.Text.Json.JsonDocument.Parse(json).RootElement;
            var email = doc.GetProperty("userPrincipalName").GetString() ?? "";
            var azureIdStr = doc.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;

            // Validación de dominio institucional (opcional — no rompe si AzureAd:AllowedDomain no está configurado)
            var allowedDomain = _cfg["AzureAd:AllowedDomain"];
            if (!string.IsNullOrWhiteSpace(allowedDomain) &&
                !email.EndsWith($"@{allowedDomain}", StringComparison.OrdinalIgnoreCase))
            {
                throw new UnauthorizedAccessException("Solo se permiten cuentas institucionales.");
            }

            var user = await _users.FindByEmailAsync(email);
            if (user is null) return null;
            _logger.LogInformation("***************usuario a conectar: {user}, {email}", user, email);

            // Sincronizar AzureObjectId en cada login para que el cambio de contraseña funcione
            if (azureIdStr != null && Guid.TryParse(azureIdStr, out var parsedObjectId))
                await _users.SyncAzureObjectIdAsync(user.Id, parsedObjectId);
            var roles = await _users.GetRolesAsync(user.Id);
            _logger.LogInformation("***************usuario tiene roles: {roles}", roles);
            var adGroups = await GetAdGroupsAsync(email);
            _logger.LogInformation("***************usuario tiene roles: {adGroups}", adGroups);
            var hrEmployeeId = await _users.GetHrEmployeeIdAsync(user.Id);
            var access = _tokens.Create(user.Id, email, roles, adGroups, hrEmployeeId);
            var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var refreshHash = _tokens.Hash(refresh);
            var session = await _auth.CreateSessionAsync(user.Id, access, refreshHash, DateTime.Now.AddDays(7), null, null);

            await _users.SetLastLoginAsync(user.Id, DateTime.Now);
            await _auth.InsertLoginAsync(user.Id, email, true, "AzureAD", "Success", null, session.SessionId, ipAddress, userAgent, deviceInfo);

            return new TokenPair(access, refresh);
        }

        private async Task<string[]> GetAdGroupsAsync(string email)
        {
            try
            {
                var dir = _identityResolver.GetDirectory("LocalAd");
                var adUser = await dir.GetUserByEmailAsync(email);
                if (adUser is null)
                {
                    _logger.LogInformation("[AD-GROUPS] Usuario {Email} no encontrado en AD local, se omiten grupos", email);
                    return [];
                }
                var groups = await dir.GetUserGroupsAsync(adUser.Id);
                var names = groups.Select(g => g.Name).ToArray();
                _logger.LogInformation("[AD-GROUPS] {Count} grupos obtenidos del AD para {Email}: {Groups}",
                    names.Length, email, string.Join(", ", names));
                return names;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AD-GROUPS] Error al consultar AD para {Email}, se continúa sin grupos", email);
                return [];
            }
        }
    }
}
