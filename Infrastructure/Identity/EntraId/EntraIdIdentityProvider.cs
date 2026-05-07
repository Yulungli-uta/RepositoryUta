using System.Net.Http.Headers;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.EntraId
{
    /// <summary>
    /// Autentica usuarios contra Entra ID usando ROPC (Resource Owner Password Credentials) vía HTTP directo.
    /// IConfidentialClientApplication no expone ROPC; se llama directamente al token endpoint.
    /// Solo válido cuando la política de CA lo permite; para flujos interactivos usar AzureAuthService.
    /// </summary>
    public sealed class EntraIdIdentityProvider : IIdentityProvider
    {
        private readonly IHttpClientFactory _http;
        private readonly IConfiguration _cfg;
        private readonly ILogger<EntraIdIdentityProvider> _logger;

        public string ProviderName => "EntraId";

        public EntraIdIdentityProvider(IHttpClientFactory http, IConfiguration cfg, ILogger<EntraIdIdentityProvider> logger)
        {
            _http = http;
            _cfg = cfg;
            _logger = logger;
        }

        public async Task<ProviderAuthResult> AuthenticateAsync(ProviderAuthRequest request, CancellationToken ct = default)
        {
            var tenantId = _cfg["AzureAd:TenantId"]!;
            var clientId = _cfg["AzureAd:ClientId"]!;
            var clientSecret = _cfg["AzureAd:ClientSecret"]!;

            var client = _http.CreateClient();
            var body = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["username"] = request.Username,
                ["password"] = request.Password,
                ["scope"] = "openid profile email"
            });

            try
            {
                var response = await client.PostAsync(
                    $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", body, ct);

                var json = await response.Content.ReadAsStringAsync(ct);
                var doc = JsonDocument.Parse(json).RootElement;

                if (!response.IsSuccessStatusCode)
                {
                    var err = doc.TryGetProperty("error_description", out var d) ? d.GetString() : "Unknown error";
                    _logger.LogWarning("Entra ID rechazó ROPC para {Email}: {Error}", request.Username, err);
                    return new ProviderAuthResult(false, null, null, "Invalid credentials");
                }

                var claims = new Dictionary<string, string>();
                if (doc.TryGetProperty("id_token", out var idTokenProp))
                {
                    var parts = idTokenProp.GetString()?.Split('.') ?? [];
                    if (parts.Length >= 2)
                    {
                        var payload = JsonDocument.Parse(
                            System.Text.Encoding.UTF8.GetString(
                                Convert.FromBase64String(PadBase64(parts[1])))).RootElement;
                        foreach (var prop in payload.EnumerateObject())
                            claims[prop.Name] = prop.Value.ToString();
                    }
                }

                var email = claims.GetValueOrDefault("preferred_username") ?? request.Username;
                var displayName = claims.GetValueOrDefault("name") ?? email;

                _logger.LogInformation("Entra ID autenticó usuario {Email}", email);
                return new ProviderAuthResult(true, email, displayName, Claims: claims);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en ROPC Entra ID para {Email}", request.Username);
                return new ProviderAuthResult(false, null, null, "Identity provider unavailable");
            }
        }

        private static string PadBase64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            return (s.Length % 4) switch
            {
                2 => s + "==",
                3 => s + "=",
                _ => s
            };
        }
    }
}
