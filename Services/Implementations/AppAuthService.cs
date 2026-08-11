using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Cryptography;
using System.Text;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Utilities;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class AppAuthService : IAppAuthService
    {
        private readonly AuthDbContext _context;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AppAuthService> _logger;
        private readonly IMemoryCache _cache;
        private readonly IConfiguration _configuration;

        public AppAuthService(AuthDbContext context, ITokenService tokenService, ILogger<AppAuthService> logger, IMemoryCache cache, IConfiguration configuration)
        {
            _context = context;
            _tokenService = tokenService;
            _logger = logger;
            _cache = cache;
            _configuration = configuration;
        }

        public async Task<AppAuthResponse> AuthenticateApplicationAsync(string clientId, string clientSecret, string? ipAddress, string? userAgent)
        {
            try
            {
                var app = await _context.Applications
                    .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (app == null)
                {
                    _logger.LogWarning("Aplicación no encontrada o inactiva: {ClientId}", clientId);
                    return new AppAuthResponse(false, "Invalid client credentials", null, null, null, null);
                }

                if (!SecretMatches(app.ClientSecretHash, _tokenService.Hash(clientSecret)))
                {
                    _logger.LogWarning("Secret inválido para aplicación: {ClientId}", clientId);
                    return new AppAuthResponse(false, "Invalid client credentials", null, null, null, null);
                }

                var tokenId = Guid.NewGuid();
                // Vida fija de 60 min para tokens app-a-app (client credentials), independiente
                // del parámetro Jwt:AccessTokenLifetimeMinutes de auth.tbl_AppParams (ese es
                // solo para tokens de usuario). Se pasa explícitamente para que el claim `exp`
                // real del JWT coincida siempre con el expiresAt devuelto al llamador.
                var appTokenLifetime = TimeSpan.FromMinutes(60);
                var expiresAt = DateTime.Now.Add(appTokenLifetime);
                var configuredRoles = _configuration.GetSection($"AppAuth:ClientRoles:{app.ClientId}").Get<string[]>();
                var tokenRoles = configuredRoles is { Length: > 0 } ? configuredRoles : new[] { "Application" };
                var token = await _tokenService.CreateAppTokenAsync(tokenId, app.ClientId, tokenRoles, appTokenLifetime);

                app.LastUsedAt = DateTime.Now;

                _context.LegacyAuthLogs.Add(new LegacyAuthLog
                {
                    ApplicationId = app.Id,
                    UserEmail     = app.ClientId,
                    AuthResult    = "Success",
                    AuthType      = "ClientCredentials",
                    IpAddress     = ipAddress ?? "",
                    UserAgent     = userAgent ?? "",
                    CreatedAt     = DateTime.Now,
                });
                await _context.SaveChangesAsync();

                _logger.LogInformation("Token de aplicación creado para: {ClientId}", clientId);
                return new AppAuthResponse(true, "Authentication successful", token, tokenId, expiresAt, app.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error autenticando aplicación: {ClientId}", clientId);
                return new AppAuthResponse(false, "Internal server error", null, null, null, null);
            }
        }

        public async Task<LegacyAuthResponse> AuthenticateUserLegacyAsync(string clientId, string clientSecret, string userEmail, string password, bool includePermissions, string? ipAddress, string? userAgent)
        {
            var startTime = DateTime.Now;
            Guid? applicationId = null;
            Guid? userId = null;

            try
            {
                var app = await _context.Applications
                    .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (app == null)
                    return await FailLegacyAsync(applicationId, userId, userEmail, "Invalid application", ipAddress, userAgent, startTime);

                applicationId = app.Id;

                if (!SecretMatches(app.ClientSecretHash, _tokenService.Hash(clientSecret)))
                    return await FailLegacyAsync(applicationId, userId, userEmail, "Invalid application credentials", ipAddress, userAgent, startTime);

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == userEmail);

                if (user == null)
                    return await FailLegacyAsync(applicationId, userId, userEmail, "User not found", ipAddress, userAgent, startTime);

                userId = user.Id;

                if (!user.IsActive)
                    return await FailLegacyAsync(applicationId, userId, userEmail, "User is inactive", ipAddress, userAgent, startTime);

                if (user.UserType == "AzureAD")
                    return await FailLegacyAsync(applicationId, userId, userEmail, "Azure AD users must authenticate through Azure", ipAddress, userAgent, startTime);

                if (user.UserType == "Local")
                {
                    var credentials = await _context.LocalUserCredentials
                        .FirstOrDefaultAsync(c => c.UserId == user.Id);

                    if (credentials == null)
                        return await FailLegacyAsync(applicationId, userId, userEmail, "No local credentials found", ipAddress, userAgent, startTime);

                    if (credentials.IsLocked)
                        return await FailLegacyAsync(applicationId, userId, userEmail, "Account is locked", ipAddress, userAgent, startTime);

                    if (!PasswordHasher.Verify(password, credentials.PasswordHash))
                    {
                        credentials.FailedAttempts++;
                        credentials.LastFailedAttempt = DateTime.Now;
                        if (credentials.FailedAttempts >= 5)
                            credentials.IsLocked = true;
                        await _context.SaveChangesAsync();
                        return await FailLegacyAsync(applicationId, userId, userEmail, "Invalid password", ipAddress, userAgent, startTime);
                    }

                    credentials.FailedAttempts = 0;
                    credentials.LastFailedAttempt = null;
                    await _context.SaveChangesAsync();
                }

                user.LastLogin = DateTime.Now;
                await _context.SaveChangesAsync();

                var response = new LegacyAuthResponse(true, "Authentication successful",
                    user.Id, user.Email, user.DisplayName, user.UserType, null, null);

                if (includePermissions)
                {
                    var activeUserRoles = _context.UserRoles
                        .Where(ur => ur.UserId == user.Id && !ur.IsDeleted &&
                                     (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.Now));

                    var roles = await activeUserRoles
                        .Join(_context.Roles, ur => ur.RoleId, r => r.Id,
                              (ur, r) => new { r.Id, r.Name, r.Description })
                        .ToListAsync();

                    var permissions = await activeUserRoles
                        .Join(_context.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (ur, rp) => rp)
                        .Join(_context.Permissions, rp => rp.PermissionId, p => p.Id, (rp, p) => p)
                        .Where(p => !p.IsDeleted)
                        .Select(p => new { p.Id, p.Name, p.Module, p.Action, p.Description })
                        .Distinct()
                        .ToListAsync();

                    response = response with { Roles = roles, Permissions = permissions };
                }

                await LogAuthAttempt(applicationId.Value, userId, userEmail, "Success", null, ipAddress, userAgent, startTime);
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante autenticación legacy para usuario {Email}", userEmail);
                await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, "Error", ex.Message, ipAddress, userAgent, startTime);
                return new LegacyAuthResponse(false, "Internal server error", null, null, null, null, null, null);
            }
        }

        public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId)
        {
            try
            {
                if (!Guid.TryParse(token, out var tokenGuid))
                    return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired", null);

                var userSession = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionId == tokenGuid && s.IsActive && s.ExpiresAt > DateTime.Now);

                if (userSession != null)
                    return new ValidateTokenResponse(true, "User token", userSession.ExpiresAt, userSession.UserId, userSession.SessionId, "Token is valid", null);

                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al validar token en AppAuthService");
                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Error validating token", null);
            }
        }

        public async Task<object?> GetApplicationStatsAsync(string clientId)
        {
            try
            {
                var app = await _context.Applications
                    .FirstOrDefaultAsync(a => a.ClientId == clientId && !a.IsDeleted);

                if (app == null) return null;

                var cutoff7Days = DateTime.Now.AddDays(-7);
                var appId = app.Id;
                var logAgg = await _context.LegacyAuthLogs
                    .Where(l => l.ApplicationId == appId)
                    .GroupBy(l => l.ApplicationId)
                    .Select(g => new
                    {
                        Total = g.Count(),
                        Successful = g.Count(l => l.AuthResult == "Success"),
                        Last7Days = g.Count(l => l.CreatedAt >= cutoff7Days)
                    })
                    .FirstOrDefaultAsync();

                var stats = new
                {
                    ApplicationId = app.Id,
                    app.Name,
                    app.ClientId,
                    app.IsActive,
                    app.CreatedAt,
                    TotalAuthAttempts = logAgg?.Total ?? 0,
                    SuccessfulAuths = logAgg?.Successful ?? 0,
                    AuthsLast7Days = logAgg?.Last7Days ?? 0,
                    ActiveTokens = 0
                };

                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error obteniendo estadísticas de aplicación: {ClientId}", clientId);
                return null;
            }
        }

        private static bool SecretMatches(string expectedHash, string actualHash)
        {
            var expectedBytes = Encoding.UTF8.GetBytes(expectedHash);
            var actualBytes = Encoding.UTF8.GetBytes(actualHash);
            if (expectedBytes.Length != actualBytes.Length) return false;
            return CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        private async Task<LegacyAuthResponse> FailLegacyAsync(Guid? applicationId, Guid? userId, string userEmail, string reason, string? ipAddress, string? userAgent, DateTime startTime)
        {
            await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, "Failed", reason, ipAddress, userAgent, startTime);
            return new LegacyAuthResponse(false, reason, null, null, null, null, null, null);
        }

        private async Task LogAuthAttempt(Guid applicationId, Guid? userId, string userEmail, string authResult, string? failureReason, string? ipAddress, string? userAgent, DateTime startTime)
        {
            try
            {
                _context.LegacyAuthLogs.Add(new LegacyAuthLog
                {
                    ApplicationId = applicationId,
                    UserId = userId,
                    UserEmail = userEmail,
                    AuthResult = authResult,
                    FailureReason = failureReason,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds
                });
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error registrando intento de autenticación");
            }
        }
    }
}
