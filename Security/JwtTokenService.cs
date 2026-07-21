using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WsSeguUta.AuthSystem.API.Data;

namespace WsSeguUta.AuthSystem.API.Security
{
    public sealed class JwtTokenService
    {
        private const string AccessTokenLifetimeParamKey = "Jwt:AccessTokenLifetimeMinutes";
        private static readonly TimeSpan ParamCacheDuration = TimeSpan.FromMinutes(5);

        private readonly RsaKeyProvider _keys;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly TimeSpan _fallbackLifetime;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IMemoryCache _cache;
        private readonly ILogger<JwtTokenService> _logger;

        public JwtTokenService(
            IConfiguration cfg,
            RsaKeyProvider keys,
            IServiceScopeFactory scopeFactory,
            IMemoryCache cache,
            ILogger<JwtTokenService> logger)
        {
            _keys = keys;
            _scopeFactory = scopeFactory;
            _cache = cache;
            _logger = logger;
            _issuer = cfg["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
            _audience = cfg["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

            // Fallback si auth.tbl_AppParams no tiene el parámetro (instalación nueva
            // o fila borrada por error): usa appsettings.json, y si tampoco está, 30 min.
            var configuredMinutes = cfg.GetValue<int?>("Jwt:AccessTokenLifetimeMinutes");
            _fallbackLifetime = TimeSpan.FromMinutes(configuredMinutes is > 0 ? configuredMinutes.Value : 30);
        }

        public Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, TimeSpan? lifetime = null, int? hrEmployeeId = null, CancellationToken ct = default)
            => CreateAsync(userId, email, roles, [], lifetime, hrEmployeeId, ct);

        public async Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups, TimeSpan? lifetime = null, int? hrEmployeeId = null, CancellationToken ct = default)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new(JwtRegisteredClaimNames.Email, email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(ClaimTypes.NameIdentifier, userId.ToString()),
                new(ClaimTypes.Name, email)
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
            claims.AddRange(adGroups.Select(g => new Claim("ad_group", g)));
            if (hrEmployeeId.HasValue)
                claims.Add(new Claim("employeeId", hrEmployeeId.Value.ToString()));

            var effectiveLifetime = lifetime ?? await GetAccessTokenLifetimeAsync(ct);

            var token = new JwtSecurityToken(
                _issuer,
                _audience,
                claims,
                expires: DateTime.Now.Add(effectiveLifetime),
                signingCredentials: new SigningCredentials(_keys.SigningKey, SecurityAlgorithms.RsaSha256));

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        /// <summary>
        /// Lee auth.tbl_AppParams['Jwt:AccessTokenLifetimeMinutes'] (gestionable solo por
        /// Administrador/R_DITIC vía AppParamsController) con caché de 5 min para no pegarle
        /// a la BD en cada login/refresh. Si la fila no existe o la BD falla, cae a
        /// appsettings.json y luego a 30 min — la emisión de tokens nunca debe bloquearse
        /// por un problema de lectura de un parámetro de configuración.
        /// </summary>
        private async Task<TimeSpan> GetAccessTokenLifetimeAsync(CancellationToken ct)
        {
            if (_cache.TryGetValue(AccessTokenLifetimeParamKey, out TimeSpan cached))
                return cached;

            var lifetime = _fallbackLifetime;
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                var raw = await db.AppParams
                    .AsNoTracking()
                    .Where(p => p.Nemonic == AccessTokenLifetimeParamKey)
                    .Select(p => p.Value)
                    .FirstOrDefaultAsync(ct);

                if (int.TryParse(raw, out var minutes) && minutes > 0)
                    lifetime = TimeSpan.FromMinutes(minutes);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "No se pudo leer {ParamKey} de auth.tbl_AppParams, usando fallback de {FallbackMinutes} min", AccessTokenLifetimeParamKey, _fallbackLifetime.TotalMinutes);
            }

            _cache.Set(AccessTokenLifetimeParamKey, lifetime, ParamCacheDuration);
            return lifetime;
        }
    }
}
