using Microsoft.Extensions.Options;
using System.DirectoryServices.Protocols;
using System.Net;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd
{
    /// <summary>
    /// Autentica usuarios contra Active Directory local mediante LDAP bind.
    /// El bind prueba las credenciales directamente; no se almacena ni transmite la contraseña.
    /// </summary>
    public sealed class LocalAdIdentityProvider : IIdentityProvider
    {
        private readonly LocalAdOptions _opts;
        private readonly ILogger<LocalAdIdentityProvider> _logger;

        public string ProviderName => "LocalAd";

        public LocalAdIdentityProvider(IOptions<LocalAdOptions> opts, ILogger<LocalAdIdentityProvider> logger)
        {
            _opts = opts.Value;
            _logger = logger;
        }

        public async Task<ProviderAuthResult> AuthenticateAsync(ProviderAuthRequest request, CancellationToken ct = default)
        {
            return await Task.Run(() => AuthenticateInternal(request), ct);
        }

        private ProviderAuthResult AuthenticateInternal(ProviderAuthRequest request)
        {
            // Construye el UPN para el bind: usuario@dominio o DOMINIO\usuario
            var bindDn = request.Username.Contains('@')
                ? request.Username
                : string.IsNullOrWhiteSpace(_opts.NetBiosDomain)
                    ? request.Username
                    : $"{_opts.NetBiosDomain}\\{request.Username}";

            LdapConnection? conn = null;
            try
            {
                conn = BuildConnection(bindDn, request.Password);

                // Bind exitoso = credenciales válidas. Busca atributos del usuario.
                var entry = SearchUser(conn, request.Username);

                var displayName = entry?.GetValueOrDefault("displayName") ?? request.Username;
                var email = entry?.GetValueOrDefault("mail")
                    ?? entry?.GetValueOrDefault("userPrincipalName")
                    ?? request.Username;

                _logger.LogInformation("AD local autenticó usuario {User}", request.Username);
                return new ProviderAuthResult(true, email, displayName);
            }
            catch (LdapException ex) when (ex.ErrorCode == 49)
            {
                // Error 49 = InvalidCredentials
                _logger.LogWarning("AD local rechazó credenciales para {User}", request.Username);
                return new ProviderAuthResult(false, null, null, "Invalid credentials");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error conectando a AD local para {User}", request.Username);
                return new ProviderAuthResult(false, null, null, "Directory unavailable");
            }
            finally
            {
                conn?.Dispose();
            }
        }

        internal LdapConnection BuildConnection(string bindDn, string password)
        {
            var id = new LdapDirectoryIdentifier(_opts.Server, _opts.Port, false, false);
            var creds = new NetworkCredential(bindDn, password);
            var conn = new LdapConnection(id, creds, AuthType.Basic)
            {
                Timeout = TimeSpan.FromSeconds(_opts.TimeoutSeconds)
            };
            conn.SessionOptions.ProtocolVersion = 3;
            conn.Bind();
            return conn;
        }

        private Dictionary<string, string>? SearchUser(LdapConnection conn, string username)
        {
            try
            {
                var sanitized = EscapeLdapFilter(username);
                var filter = $"(&(objectClass=user)(|(sAMAccountName={sanitized})(userPrincipalName={sanitized})(mail={sanitized})))";
                var attrs = new[] { "displayName", "mail", "userPrincipalName", "sAMAccountName", "givenName", "sn", "department", "title" };

                var req = new SearchRequest(_opts.BaseDn, filter, SearchScope.Subtree, attrs);
                var resp = (SearchResponse)conn.SendRequest(req);

                if (resp.Entries.Count == 0) return null;

                var entry = resp.Entries[0];
                var result = new Dictionary<string, string>();
                foreach (var attr in attrs)
                {
                    if (entry.Attributes[attr]?.Count > 0)
                        result[attr] = entry.Attributes[attr][0]?.ToString() ?? "";
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "No se pudo obtener atributos de usuario {User} en AD", username);
                return null;
            }
        }

        /// <summary>Escapa caracteres especiales LDAP para prevenir LDAP injection.</summary>
        private static string EscapeLdapFilter(string value)
        {
            return value
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }
    }
}
