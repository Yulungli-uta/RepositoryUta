using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AutoMapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.SignalR;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Security;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Utilities;
using WsSeguUta.AuthSystem.API.Hubs;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class TokenService : ITokenService
    {
        private readonly JwtTokenService _jwt;
        public TokenService(JwtTokenService jwt) => _jwt = jwt;
        public string Create(Guid userId, string email, IEnumerable<string> roles) => _jwt.Create(userId, email, roles);
        public string Hash(string input) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }

    public class AuthService : IAuthService
    {
        private readonly IUserRepository _users;
        private readonly IAuthRepository _auth;
        private readonly ITokenService _tokens;
        private readonly AuthDbContext _context;
        private readonly IConfiguration _cfg;

        public AuthService(IUserRepository users, IAuthRepository auth, ITokenService tokens, AuthDbContext context, IConfiguration cfg)
        {
            _users = users;
            _auth = auth;
            _tokens = tokens;
            _context = context;
            _cfg = cfg;
        }

        public async Task<TokenPair?> LoginLocalAsync(string email, string password)
        {
            var now = DateTime.UtcNow;
            var u = await _users.FindByEmailAsync(email);
            if (u is null || !u.IsActive || !string.Equals(u.UserType, "Local", StringComparison.OrdinalIgnoreCase))
            {
                await _auth.RecordFailedAttemptAsync(email, null, null, "User not found/inactive");
                await _auth.InsertLoginAsync(null, email, false, "Local", "Failed", "User not found/inactive", null, null, null, null);
                return null;
            }

            var cred = await _users.GetLocalCredAsync(u.Id);
            if (cred is null)
            {
                await _auth.RecordFailedAttemptAsync(email, null, null, "No credentials");
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "No credentials", null, null, null, null);
                return null;
            }

            if (cred.IsLocked || (cred.LockedUntil.HasValue && cred.LockedUntil.Value > now))
            {
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Blocked", "Locked account", null, null, null, null);
                return null;
            }

            if (cred.PasswordExpiresAt.HasValue && cred.PasswordExpiresAt.Value <= now)
            {
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "Password expired", null, null, null, null);
                return null;
            }

            var ok = PasswordHasher.Verify(password, cred.PasswordHash);
            if (!ok)
            {
                cred.FailedAttempts += 1;
                cred.LastFailedAttempt = now;
                if (cred.FailedAttempts >= 5)
                {
                    cred.LockedUntil = now.AddMinutes(30);
                    cred.IsLocked = true;
                }
                await _users.UpdateLocalCredAsync(cred);
                await _auth.RecordFailedAttemptAsync(email, null, null, "Invalid password");
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", cred.IsLocked ? "Blocked" : "Failed", "Invalid password", null, null, null, null);
                return null;
            }

            cred.FailedAttempts = 0;
            cred.IsLocked = false;
            cred.LockedUntil = null;
            await _users.UpdateLocalCredAsync(cred);

            var roles = await _users.GetRolesAsync(u.Id);
            var access = _tokens.Create(u.Id, u.Email, roles);
            Console.WriteLine($"Access token created for {email}: {access}");
            var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var refreshHash = _tokens.Hash(refresh);
            var expiresAt = now.AddDays(7);
            var session = await _auth.CreateSessionAsync(u.Id, access, refreshHash, expiresAt, null, null);
            Console.WriteLine($"Session created for {email}, session ID: {session.SessionId}");
            await _users.SetLastLoginAsync(u.Id, now);
            Console.WriteLine($"Last login updated for {email}");
            await _auth.InsertLoginAsync(u.Id, email, true, "Local", "Success", null, session.SessionId, null, null, null);
            Console.WriteLine($"Login successful for {email}, session {session.SessionId}");
            return new TokenPair(access, refresh);
        }

        public async Task<TokenPair?> RefreshAsync(string refreshToken)
        {
            var hash = _tokens.Hash(refreshToken);
            var found = await _auth.GetActiveSessionByRefreshHashAsync(hash);
            if (found is null) return null;
            var (sess, u) = found.Value;
            var roles = await _users.GetRolesAsync(u.Id);
            var newAccess = _tokens.Create(u.Id, u.Email, roles);
            var newRefresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var newHash = _tokens.Hash(newRefresh);
            var newExp = DateTime.UtcNow.AddDays(7);
            await _auth.RevokeSessionAsync(sess.SessionId, "Rotated");
            await _auth.CreateSessionAsync(u.Id, newAccess, newHash, newExp, sess.DeviceInfo, sess.IpAddress);
            return new TokenPair(newAccess, newRefresh);
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            var hash = _tokens.Hash(refreshToken);
            var found = await _auth.GetActiveSessionByRefreshHashAsync(hash);
            if (found is null) return true;
            await _auth.RevokeSessionAsync(found.Value.Sess.SessionId, "Logout");
            return true;
        }

        public async Task<object?> MeAsync(Guid userId)
        {
            var u = await _users.FindByIdAsync(userId);
            if (u is null) return null;
            var roles = await _users.GetRolesAsync(userId);
            return new { u.Id, u.Email, u.DisplayName, u.UserType, u.LastLogin, Roles = roles };
        }

        public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId)
        {
            try
            {
                var jwtHandler = new JwtSecurityTokenHandler();
                if (jwtHandler.CanReadToken(token))
                {
                    Console.WriteLine($"*********** Token is a valid JWT format");

                    var key = _cfg["Jwt:Key"] ?? "dev";
                    var issuer = _cfg["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
                    var audience = _cfg["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

                    var validationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = issuer,
                        ValidAudience = audience,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                        ClockSkew = TimeSpan.Zero
                    };

                    try
                    {
                        var principal = jwtHandler.ValidateToken(token, validationParameters, out var validatedToken);

                        var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                        var emailClaim = principal.FindFirst(ClaimTypes.Name)?.Value;
                        var rolesClaims = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

                        var rolesText = rolesClaims != null ? string.Join(",", rolesClaims) : "(none)";

                        if (Guid.TryParse(userIdClaim, out var userId))
                        {
                            var user = await _users.FindByIdAsync(userId);
                            Console.WriteLine($"**********userid: {user.Id}, email: {user.Email}");
                            if (user != null && user.IsActive)
                            {
                                return new ValidateTokenResponse(
                                  IsValid: true,
                                  TokenType: "JWT",
                                  ExpiresAt: ((JwtSecurityToken)validatedToken).ValidTo,
                                  UserId: userId,
                                  SessionId: null,
                                  Message: "Token is valid",
                                  Email: user.Email
                                );
                            }
                        }

                        Console.WriteLine($"*********** JWT validation failed: User not found or inactive");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "User not found or inactive", null);
                    }
                    catch (SecurityTokenExpiredException)
                    {
                        Console.WriteLine($"*********** JWT validation failed: Token expired");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token expired", null);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"*********** JWT validation failed: {ex.Message}");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token validation failed", null);
                    }
                }

                Console.WriteLine($"*********** Token is not JWT, trying as session GUID");
                if (Guid.TryParse(token, out var tokenGuid))
                {
                    var session = await _context.UserSessions
                      .FirstOrDefaultAsync(s => s.SessionId == tokenGuid && s.IsActive && s.ExpiresAt > DateTime.UtcNow);
                    if (session != null)
                    {
                        Console.WriteLine($"*********** Session token validated successfully");
                        return new ValidateTokenResponse(true, "User token", session.ExpiresAt, session.UserId, session.SessionId, "Token is valid", null);
                    }
                }

                Console.WriteLine($"*********** Token validation failed: Invalid format");
                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired", null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"*********** Token validation error: {ex.Message}");
                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Error validating token", null);
            }
        }

        public async Task<bool> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
        {
            var user = await _users.FindByIdAsync(userId);
            if (user is null || !user.IsActive || !string.Equals(user.UserType, "Local", StringComparison.OrdinalIgnoreCase))
                return false;

            var cred = await _users.GetLocalCredAsync(userId);
            if (cred is null)
                return false;

            if (!PasswordHasher.Verify(currentPassword, cred.PasswordHash))
                return false;

            if (PasswordHasher.Verify(newPassword, cred.PasswordHash))
                return false;

            var newPasswordHash = PasswordHasher.Hash(newPassword);

            cred.PasswordHash = newPasswordHash;
            cred.PasswordCreatedAt = DateTime.UtcNow;
            cred.MustChangePassword = false;
            cred.PasswordExpiresAt = DateTime.UtcNow.AddDays(90);

            await _users.UpdateLocalCredAsync(cred);

            _context.PasswordHistory.Add(new PasswordHistory
            {
                UserId = userId,
                PasswordHash = newPasswordHash,
                CreatedAt = DateTime.UtcNow
            });

            await _context.SaveChangesAsync();

            return true;
        }
    }

    public class AzureAuthService : IAzureAuthService
    {
        private readonly IConfiguration _cfg;
        private readonly IHttpClientFactory _http;
        private readonly IUserRepository _users;
        private readonly ITokenService _tokens;
        private readonly IAuthRepository _auth;
        private readonly IMemoryCache _cache;
        private readonly INotificationService _notificationService;

        public AzureAuthService(IConfiguration cfg, IHttpClientFactory http, IUserRepository users, ITokenService tokens, IAuthRepository auth, IMemoryCache cache, INotificationService notificationService)
        {
            _cfg = cfg;
            _http = http;
            _users = users;
            _tokens = tokens;
            _auth = auth;
            _cache = cache;
            _notificationService = notificationService;
        }

        public async Task<(string Url, string State)> BuildAuthUrlAsync(string? clientId = null, string? browserId = null)
        {
            var stateGuid = Guid.NewGuid().ToString("N");

            var stateData = new
            {
                stateId = stateGuid,
                clientId = clientId,
                browserId = browserId,
                timestamp = DateTime.UtcNow.ToString("O"),
                source = "azure_auth"
            };

            var stateJson = System.Text.Json.JsonSerializer.Serialize(stateData);
            var stateEncoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(stateJson));

            _cache.Set($"ms_state:{stateGuid}", stateData, TimeSpan.FromMinutes(10));

            var tenant = _cfg["AzureAd:TenantId"];
            var clientIdAzure = _cfg["AzureAd:ClientId"];
            var authority = $"https://login.microsoftonline.com/{tenant}/v2.0";
            var redirect = _cfg["AzureAd:RedirectUri"]!;
            var cca = ConfidentialClientApplicationBuilder.Create(clientIdAzure)
              .WithAuthority(authority)
              .WithClientSecret(_cfg["AzureAd:ClientSecret"])
              .WithRedirectUri(redirect)
              .Build();

            var scopes = new[] { "openid", "profile", "email", "offline_access", "User.Read" };

            var url = await cca.GetAuthorizationRequestUrl(scopes)
              .WithRedirectUri(redirect)
              .WithExtraQueryParameters(new Dictionary<string, string> { { "state", stateEncoded } })
              .ExecuteAsync();

            Console.WriteLine($"Azure auth URL generated with clientId: {clientId}, stateId: {stateGuid}, browserID: {browserId}");
            return (url.ToString(), stateEncoded);
        }

        public async Task<TokenPair?> HandleCallbackAsync(string code, string state)
        {
            var stateJson = Encoding.UTF8.GetString(Convert.FromBase64String(state));
            var stateData = System.Text.Json.JsonDocument.Parse(stateJson).RootElement;
            var stateId = stateData.GetProperty("stateId").GetString();
            Console.WriteLine($"*****************Handling Azure callback with statejson: {stateJson}, statedata: {stateData}. stateId: {stateId}");

            if (!_cache.TryGetValue($"ms_state:{stateId}", out _)) return null;

            var tenant = _cfg["AzureAd:TenantId"];
            var clientId = _cfg["AzureAd:ClientId"];
            var authority = $"https://login.microsoftonline.com/{tenant}/v2.0";
            var redirect = _cfg["AzureAd:RedirectUri"]!;
            var cca = ConfidentialClientApplicationBuilder.Create(clientId)
              .WithAuthority(authority)
              .WithClientSecret(_cfg["AzureAd:ClientSecret"])
              .WithRedirectUri(redirect)
              .Build();

            var scopes = new[] { "openid", "profile", "email", "offline_access", "User.Read" };
            var result = await cca.AcquireTokenByAuthorizationCode(scopes, code).ExecuteAsync();

            var client = _http.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);
            var res = await client.GetAsync("https://graph.microsoft.com/v1.0/me");
            res.EnsureSuccessStatusCode();
            var json = await res.Content.ReadAsStringAsync();
            var email = System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("userPrincipalName").GetString() ?? "";

            var user = await _users.FindByEmailAsync(email);
            Console.WriteLine($"User found in local DB: {user != null}");
            if (user is null) return null;

            var roles = await _users.GetRolesAsync(user.Id);
            var access = _tokens.Create(user.Id, email, roles);
            var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var refreshHash = _tokens.Hash(refresh);
            var exp = DateTime.UtcNow.AddDays(7);
            var session = await _auth.CreateSessionAsync(user.Id, access, refreshHash, exp, null, null);

            await _users.SetLastLoginAsync(user.Id, DateTime.UtcNow);
            Console.WriteLine($"Last login updated for Azure AD user {email}");

            return new TokenPair(access, refresh);
        }
    }

    public class MenuService : IMenuService
    {
        private readonly IMenuRepository _repo;
        public MenuService(IMenuRepository repo) => _repo = repo;
        public Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId) => _repo.GetMenuByUserAsync(userId);
    }

    public class CrudService<TEntity, TCreate, TUpdate> : ICrudService<TEntity, TCreate, TUpdate> where TEntity : class, new()
    {
        private readonly IGenericRepository<TEntity> _repo;
        private readonly IMapper _map;
        public CrudService(IGenericRepository<TEntity> repo, IMapper map) { _repo = repo; _map = map; }
        public Task<IEnumerable<TEntity>> ListAsync(int page, int size) => _repo.GetAllAsync(page, size);
        public Task<TEntity?> GetAsync(params object[] key) => _repo.GetAsync(key);
        public async Task<TEntity> CreateAsync(TCreate dto) { var e = _map.Map<TEntity>(dto); return await _repo.AddAsync(e); }
        public async Task<TEntity?> UpdateAsync(object key, TUpdate dto)
        {
            var current = await _repo.GetAsync(key);
            if (current == null) return null;
            _map.Map(dto, current);
            return await _repo.UpdateAsync(current);
        }
        public Task<bool> DeleteAsync(params object[] key) => _repo.DeleteAsync(key);
    }

    public class AppAuthService : IAppAuthService
    {
        private readonly AuthDbContext _context;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AppAuthService> _logger;
        private readonly IMemoryCache _cache;

        public AppAuthService(AuthDbContext context, ITokenService tokenService, ILogger<AppAuthService> logger, IMemoryCache cache)
        {
            _context = context;
            _tokenService = tokenService;
            _logger = logger;
            _cache = cache;
        }

        public async Task<AppAuthResponse> AuthenticateApplicationAsync(string clientId, string clientSecret, string? ipAddress, string? userAgent)
        {
            try
            {
                var app = await _context.Applications
                  .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (app == null)
                {
                    _logger.LogWarning("Application not found or inactive: {ClientId}", clientId);
                    return new AppAuthResponse(false, "Invalid client credentials", null, null, null);
                }

                var providedSecretHash = _tokenService.Hash(clientSecret);
                if (app.ClientSecretHash != providedSecretHash)
                {
                    _logger.LogWarning("Invalid client secret for application: {ClientId}", clientId);
                    return new AppAuthResponse(false, "Invalid client credentials", null, null, null);
                }

                var tokenId = Guid.NewGuid();
                var expiresAt = DateTime.UtcNow.AddMinutes(60);
                var token = _tokenService.Create(tokenId, app.ClientId, new[] { "Application" });

                var authLog = new LegacyAuthLog
                {
                    ApplicationId = app.Id,
                    UserEmail = app.ClientId,
                    AuthResult = "Success",
                    AuthType = "ClientCredentials",
                    IpAddress = "",
                    UserAgent = "",
                    CreatedAt = DateTime.UtcNow
                };

                _context.LegacyAuthLogs.Add(authLog);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Application token created successfully for: {ClientId}", clientId);
                return new AppAuthResponse(true, "Authentication successful", tokenId, expiresAt, app.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error authenticating application: {ClientId}", clientId);
                return new AppAuthResponse(false, "Internal server error", null, null, null);
            }
        }

        public async Task<LegacyAuthResponse> AuthenticateUserLegacyAsync(string clientId, string clientSecret, string userEmail, string password, bool includePermissions, string? ipAddress, string? userAgent)
        {
            var startTime = DateTime.UtcNow;
            Guid? applicationId = null;
            Guid? userId = null;
            string authResult = "Failed";
            string? failureReason = null;

            try
            {
                var app = await _context.Applications
                  .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (app == null)
                {
                    failureReason = "Invalid application";
                    goto LogAndReturn;
                }

                applicationId = app.Id;

                var providedSecretHash = _tokenService.Hash(clientSecret);
                if (app.ClientSecretHash != providedSecretHash)
                {
                    failureReason = "Invalid application credentials";
                    goto LogAndReturn;
                }

                var user = await _context.Users
                  .FirstOrDefaultAsync(u => u.Email == userEmail);

                if (user == null)
                {
                    failureReason = "User not found";
                    goto LogAndReturn;
                }

                userId = user.Id;

                if (!user.IsActive)
                {
                    failureReason = "User is inactive";
                    goto LogAndReturn;
                }

                if (user.UserType == "Local")
                {
                    var credentials = await _context.LocalUserCredentials
                      .FirstOrDefaultAsync(c => c.UserId == user.Id);

                    if (credentials == null)
                    {
                        failureReason = "No local credentials found";
                        goto LogAndReturn;
                    }

                    if (credentials.IsLocked)
                    {
                        failureReason = "Account is locked";
                        goto LogAndReturn;
                    }

                    var providedPasswordHash = _tokenService.Hash(password);
                    if (credentials.PasswordHash != providedPasswordHash)
                    {
                        credentials.FailedAttempts++;
                        credentials.LastFailedAttempt = DateTime.UtcNow;

                        var maxAttempts = 5;
                        if (credentials.FailedAttempts >= maxAttempts)
                        {
                            credentials.IsLocked = true;
                        }

                        await _context.SaveChangesAsync();
                        failureReason = "Invalid password";
                        goto LogAndReturn;
                    }

                    credentials.FailedAttempts = 0;
                    credentials.LastFailedAttempt = null;
                    await _context.SaveChangesAsync();
                }
                else if (user.UserType == "AzureAD")
                {
                    failureReason = "Azure AD users must authenticate through Azure";
                    goto LogAndReturn;
                }

                user.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                authResult = "Success";

                var response = new LegacyAuthResponse(
                  true,
                  "Authentication successful",
                  user.Id,
                  user.Email,
                  user.DisplayName,
                  user.UserType,
                  null,
                  null
                );

                if (includePermissions)
                {
                    var roles = await _context.UserRoles
                      .Where(ur => ur.UserId == user.Id && !ur.IsDeleted &&
                                  (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.UtcNow))
                      .Join(_context.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => new { r.Id, r.Name, r.Description })
                      .Where(r => r != null)
                      .ToListAsync();

                    var permissions = await _context.UserRoles
                      .Where(ur => ur.UserId == user.Id && !ur.IsDeleted &&
                                  (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.UtcNow))
                      .Join(_context.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (ur, rp) => rp)
                      .Join(_context.Permissions, rp => rp.PermissionId, p => p.Id, (rp, p) => p)
                      .Where(p => !p.IsDeleted)
                      .Select(p => new { p.Id, p.Name, p.Module, p.Action, p.Description })
                      .Distinct()
                      .ToListAsync();

                    response = response with { Roles = roles, Permissions = permissions };
                }

                await LogAuthAttempt(applicationId.Value, userId, userEmail, authResult, failureReason, ipAddress, userAgent, startTime);

                return response;

            LogAndReturn:
                await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, authResult, failureReason, ipAddress, userAgent, startTime);

                return new LegacyAuthResponse(false, failureReason ?? "Authentication failed", null, null, null, null, null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during legacy authentication for user: {Email}", userEmail);

                await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, "Error", ex.Message, ipAddress, userAgent, startTime);

                return new LegacyAuthResponse(false, "Internal server error", null, null, null, null, null, null);
            }
        }

        public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId)
        {
            try
            {
                if (Guid.TryParse(token, out var tokenGuid))
                {
                    if (!string.IsNullOrEmpty(clientId))
                    {
                        var app = await _context.Applications
                          .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                        if (app != null)
                        {
                            return new ValidateTokenResponse(true, "Application token", DateTime.UtcNow.AddMinutes(60), null, null, "Token is valid", null);
                        }
                    }

                    var userSession = await _context.UserSessions
                      .FirstOrDefaultAsync(s => s.SessionId == tokenGuid && s.IsActive);

                    if (userSession != null && userSession.ExpiresAt > DateTime.UtcNow)
                    {
                        return new ValidateTokenResponse(true, "User token", userSession.ExpiresAt, userSession.UserId, userSession.SessionId, "Token is valid", null);
                    }
                }

                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating token");
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

                var stats = new
                {
                    ApplicationId = app.Id,
                    Name = app.Name,
                    ClientId = app.ClientId,
                    IsActive = app.IsActive,
                    CreatedAt = app.CreatedAt,
                    TotalAuthAttempts = await _context.LegacyAuthLogs.CountAsync(l => l.ApplicationId == app.Id),
                    SuccessfulAuths = await _context.LegacyAuthLogs.CountAsync(l => l.ApplicationId == app.Id && l.AuthResult == "Success"),
                    AuthsLast7Days = await _context.LegacyAuthLogs.CountAsync(l => l.ApplicationId == app.Id && l.CreatedAt >= DateTime.UtcNow.AddDays(-7)),
                    ActiveTokens = 0
                };

                return stats;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting application stats for: {ClientId}", clientId);
                return null;
            }
        }

        private async Task LogAuthAttempt(Guid applicationId, Guid? userId, string userEmail, string authResult, string? failureReason, string? ipAddress, string? userAgent, DateTime startTime)
        {
            try
            {
                var log = new LegacyAuthLog
                {
                    ApplicationId = applicationId,
                    UserId = userId,
                    UserEmail = userEmail,
                    AuthResult = authResult,
                    FailureReason = failureReason,
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    ResponseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds
                };

                _context.LegacyAuthLogs.Add(log);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error logging auth attempt");
            }
        }
    }

    // ========== IMPLEMENTACIÓN DEL SERVICIO DE NOTIFICACIONES ==========
    public class NotificationService : INotificationService
    {
        private readonly AuthDbContext _context;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<NotificationService> _logger;
        private readonly IConfiguration _configuration;
        private readonly IHubContext<NotificationHub>? _hubContext;

        public NotificationService(
          AuthDbContext context,
          IHttpClientFactory httpClientFactory,
          ILogger<NotificationService> logger,
          IConfiguration configuration,
          IHubContext<NotificationHub>? hubContext = null)
        {
            _context = context;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _configuration = configuration;
            _hubContext = hubContext;
        }

        public async Task<Guid> CreateSubscriptionAsync(Guid applicationId, string eventType, string webhookUrl, string? secretKey)
        {
            try
            {
                var appExists = await _context.Applications.AnyAsync(a => a.Id == applicationId && a.IsActive && !a.IsDeleted);
                if (!appExists)
                {
                    throw new ArgumentException("Application not found or inactive");
                }

                var subscription = new NotificationSubscription
                {
                    ApplicationId = applicationId,
                    EventType = eventType,
                    WebhookUrl = webhookUrl,
                    SecretKey = secretKey
                };

                _context.NotificationSubscriptions.Add(subscription);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Notification subscription created: {SubscriptionId} for application {ApplicationId}", subscription.Id, applicationId);
                return subscription.Id;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating notification subscription for application {ApplicationId}", applicationId);
                throw;
            }
        }

        public async Task<bool> UpdateSubscriptionAsync(Guid subscriptionId, string? webhookUrl, string? secretKey, bool? isActive)
        {
            try
            {
                var subscription = await _context.NotificationSubscriptions.FindAsync(subscriptionId);
                if (subscription == null) return false;

                if (!string.IsNullOrEmpty(webhookUrl)) subscription.WebhookUrl = webhookUrl;
                if (secretKey != null) subscription.SecretKey = secretKey;
                if (isActive.HasValue) subscription.IsActive = isActive.Value;

                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating notification subscription {SubscriptionId}", subscriptionId);
                return false;
            }
        }

        public async Task<bool> DeleteSubscriptionAsync(Guid subscriptionId)
        {
            try
            {
                var subscription = await _context.NotificationSubscriptions.FindAsync(subscriptionId);
                if (subscription == null) return false;

                _context.NotificationSubscriptions.Remove(subscription);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting notification subscription {SubscriptionId}", subscriptionId);
                return false;
            }
        }

        public async Task<IEnumerable<NotificationSubscription>> GetSubscriptionsByApplicationAsync(Guid applicationId)
        {
            var subscriptions = await _context.NotificationSubscriptions
              .Where(s => s.ApplicationId == applicationId && s.IsActive)
              .ToListAsync();

            return subscriptions;
        }

        public async Task NotifyLoginEventForApplicationAsync(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair, string browserId)
        {
            try
            {
                var application = await _context.Applications
                  .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

                if (application == null)
                {
                    Console.WriteLine($"Application with clientId {clientId} not found");
                    return;
                }

                var subscriptions = await _context.NotificationSubscriptions
                  .Where(s => s.ApplicationId == application.Id && s.EventType == "Login" && s.IsActive)
                  .ToListAsync();

                if (!subscriptions.Any())
                {
                    Console.WriteLine($"No login subscriptions found for application {clientId}");
                    return;
                }

                var eventData = await PrepareLoginEventData(userId, loginType, ipAddress, clientId, pair);
                if (eventData == null) return;

                foreach (var subscription in subscriptions)
                {
                    switch (subscription.NotificationType?.ToLower())
                    {
                        case "webhook":
                            Console.WriteLine($"*************Webhook --- EventData {eventData}, ClientId: {clientId}, BrowserId: {browserId}");
                            await SendWebhookNotification(subscription, eventData);
                            break;

                        case "websocket":
                            Console.WriteLine($"*************Websocket ---EventData {eventData}, ClientId: {clientId}, BrowserId: {browserId}");
                            await SendWebSocketNotification(subscription, eventData, clientId, browserId);
                            break;

                        case "both":
                        default:
                            await SendWebhookNotification(subscription, eventData);
                            await SendWebSocketNotification(subscription, eventData, clientId, browserId);
                            break;
                    }
                }

                Console.WriteLine($"Hybrid notifications sent for user {userId} to application {clientId}, BrowserId: {browserId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error sending hybrid notifications to {clientId}, BrowserId: {browserId} : {ex.Message}");
            }
        }

        private async Task<object?> PrepareLoginEventData(Guid userId, string loginType, string? ipAddress, string clientId, TokenPair? pair)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return null;

                var roles = await GetUserRoles(userId);
                var permissions = await GetUserPermissions(userId);

                return new
                {
                    eventType = "Login",
                    timestamp = DateTime.UtcNow,
                    context = new
                    {
                        initiatingApplication = clientId,
                        loginSource = loginType,
                        sessionScope = "specific",
                        notificationType = "hybrid"
                    },
                    data = new
                    {
                        userId,
                        email = user.Email,
                        displayName = user.DisplayName,
                        loginType,
                        ipAddress,
                        roles,
                        permissions
                    },
                    pair = pair
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error preparing login event data: {ex.Message}");
                return null;
            }
        }

        private async Task SendWebhookNotification(NotificationSubscription subscription, object eventData)
        {
            if (string.IsNullOrEmpty(subscription.WebhookUrl)) return;
            await SendWebhookAsync(subscription, eventData);
        }

        private async Task SendWebSocketNotification(NotificationSubscription subscription, object eventData, string clientId, string browserId)
        {
            var startTime = DateTime.UtcNow;

            try
            {
                Console.WriteLine($"*****************Sending WebSocket notification to application {clientId} with eventData: {eventData} browserId: {browserId}");

                if (_hubContext != null)
                {
                    if (!string.IsNullOrEmpty(browserId))
                    {
                        await _hubContext.Clients.Group($"browser_{browserId}")
                          .SendAsync("LoginNotification", eventData);
                    }
                    else
                    {
                        await _hubContext.Clients.Group($"app_{clientId}")
                          .SendAsync("LoginNotification", eventData);
                    }
                }

                var log = new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = "Login",
                    WebhookUrl = !string.IsNullOrEmpty(browserId)
                    ? $"websocket://browser_{browserId}"
                    : $"websocket://app_{clientId}",
                    HttpStatusCode = 200,
                    ResponseBody = "delivered",
                    IsSuccess = true,
                    ResponseTime = (int)(DateTime.Now - startTime).TotalMilliseconds,
                    CreatedAt = DateTime.Now
                };

                _context.NotificationLogs.Add(log);
                await _context.SaveChangesAsync();

                Console.WriteLine($"WebSocket notification sent to application {clientId}");
            }
            catch (Exception ex)
            {
                var errorLog = new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = "Login",
                    WebhookUrl = !string.IsNullOrEmpty(browserId)
                    ? $"websocket://browser_{browserId}"
                    : $"websocket://app_{clientId}",
                    HttpStatusCode = 0,
                    IsSuccess = false,
                    ResponseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds,
                    ErrorMessage = ex.Message,
                    CreatedAt = DateTime.UtcNow
                };

                _context.NotificationLogs.Add(errorLog);
                await _context.SaveChangesAsync();

                Console.WriteLine($"Error sending WebSocket notification to {clientId}: {ex.Message}");
            }
        }

        public async Task NotifyLoginEventAsync(Guid userId, string loginType, string? ipAddress, object? roles, object? permissions, TokenPair? pair, string browserId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new LoginEventData(
                  userId,
                  user.Email,
                  user.DisplayName ?? "",
                  loginType,
                  ipAddress ?? "",
                  DateTime.UtcNow,
                  roles,
                  permissions,
                  pair: pair
                );

                await SendDirectNotificationsAsync("Login", eventData);
                _logger.LogInformation("Login notification sent for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending login notification for user {UserId}", userId);
            }
        }

        public async Task NotifyLogoutEventAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new LogoutEventData(userId, user.Email, DateTime.UtcNow);
                await SendDirectNotificationsAsync("Logout", eventData);
                _logger.LogInformation("Logout notification sent for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending logout notification for user {UserId}", userId);
            }
        }

        public async Task NotifyUserCreatedEventAsync(Guid userId)
        {
            try
            {
                var user = await _context.Users.FindAsync(userId);
                if (user == null) return;

                var eventData = new UserCreatedEventData(userId, user.Email, user.DisplayName ?? "", user.UserType, user.CreatedAt);
                await SendDirectNotificationsAsync("UserCreated", eventData);
                _logger.LogInformation("User created notification sent for user {UserId}", userId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending user created notification for user {UserId}", userId);
            }
        }

        public async Task<NotificationStatsDto> GetNotificationStatsAsync()
        {
            var totalSubscriptions = await _context.NotificationSubscriptions.CountAsync();
            var activeSubscriptions = await _context.NotificationSubscriptions.CountAsync(s => s.IsActive);
            var totalLogs = await _context.NotificationLogs.CountAsync();
            var successfulLogs = await _context.NotificationLogs.CountAsync(l => l.IsSuccess);
            var failedNotifications = await _context.NotificationLogs.CountAsync(l => !l.IsSuccess);

            return new NotificationStatsDto(totalSubscriptions, activeSubscriptions, totalLogs, successfulLogs, failedNotifications);
        }

        public async Task<IEnumerable<SubscriptionStatsDto>> GetSubscriptionStatsAsync(Guid applicationId)
        {
            var subscriptions = await _context.NotificationSubscriptions
              .Where(s => s.ApplicationId == applicationId)
              .Select(s => new SubscriptionStatsDto(
                s.Id,
                s.EventType,
                s.WebhookUrl,
                s.IsActive,
                _context.NotificationLogs.Count(l => l.SubscriptionId == s.Id),
                _context.NotificationLogs.Count(l => l.SubscriptionId == s.Id && l.IsSuccess),
                _context.NotificationLogs.Count(l => l.SubscriptionId == s.Id && !l.IsSuccess),
                s.ModifiedAt
              ))
              .ToListAsync();

            return subscriptions;
        }

        public Task ProcessPendingNotificationsAsync()
        {
            _logger.LogInformation("ProcessPendingNotificationsAsync called - notifications are now sent directly");
            return Task.CompletedTask;
        }

        private async Task SendDirectNotificationsAsync(string eventType, object eventData)
        {
            try
            {
                var subscriptions = await _context.NotificationSubscriptions
                  .Where(s => s.EventType == eventType && s.IsActive)
                  .ToListAsync();

                foreach (var subscription in subscriptions)
                {
                    await SendWebhookAsync(subscription, eventData);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending direct notifications for event type {EventType}", eventType);
            }
        }

        private async Task SendWebhookAsync(NotificationSubscription subscription, object eventData)
        {
            var startTime = DateTime.UtcNow;
            var httpClient = _httpClientFactory.CreateClient();

            try
            {
                var jsonPayload = System.Text.Json.JsonSerializer.Serialize(eventData);
                var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");

                httpClient.Timeout = TimeSpan.FromSeconds(30);
                if (!string.IsNullOrEmpty(subscription.SecretKey))
                {
                    var signature = GenerateSignature(jsonPayload, subscription.SecretKey);
                    content.Headers.Add("X-Webhook-Signature", signature);
                }

                var response = await httpClient.PostAsync(subscription.WebhookUrl, content);
                var responseBody = await response.Content.ReadAsStringAsync();
                var responseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

                var log = new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = eventData.GetType().Name.Replace("EventData", ""),
                    WebhookUrl = subscription.WebhookUrl,
                    HttpStatusCode = (int)response.StatusCode,
                    ResponseBody = responseBody,
                    IsSuccess = response.IsSuccessStatusCode,
                    ResponseTime = responseTime,
                    ErrorMessage = response.IsSuccessStatusCode ? null : $"HTTP {response.StatusCode}: {responseBody}"
                };

                _context.NotificationLogs.Add(log);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Webhook sent to {WebhookUrl} with status {StatusCode}", subscription.WebhookUrl, response.StatusCode);
            }
            catch (Exception ex)
            {
                var responseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

                var errorLog = new NotificationLog
                {
                    SubscriptionId = subscription.Id,
                    EventType = eventData.GetType().Name.Replace("EventData", ""),
                    WebhookUrl = subscription.WebhookUrl,
                    HttpStatusCode = 0,
                    IsSuccess = false,
                    ResponseTime = responseTime,
                    ErrorMessage = ex.Message
                };

                _context.NotificationLogs.Add(errorLog);
                await _context.SaveChangesAsync();

                _logger.LogError(ex, "Error sending webhook to {WebhookUrl}", subscription.WebhookUrl);
            }
        }

        private async Task<IEnumerable<string>> GetUserRoles(Guid userId)
        {
            return await _context.UserRoles
              .Where(ur => ur.UserId == userId && !ur.IsDeleted)
              .Join(_context.Roles, ur => ur.RoleId, r => r.Id, (ur, r) => r.Name)
              .ToListAsync();
        }

        private async Task<IEnumerable<object>> GetUserPermissions(Guid userId)
        {
            return await _context.UserRoles
              .Where(ur => ur.UserId == userId && !ur.IsDeleted)
              .Join(_context.RolePermissions, ur => ur.RoleId, rp => rp.RoleId, (ur, rp) => rp)
              .Join(_context.Permissions, rp => rp.PermissionId, p => p.Id, (rp, p) => p)
              .Where(p => !p.IsDeleted)
              .Select(p => new { p.Id, p.Name, p.Module, p.Action, p.Description })
              .Distinct()
              .ToListAsync();
        }

        private string GenerateSignature(string payload, string? secretKey)
        {
            if (string.IsNullOrEmpty(secretKey)) return "";

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToHexString(hash).ToLower();
        }
    }
}

// ========== IMPLEMENTACIÓN DEL SERVICIO WEBSOCKET ==========
public class WebSocketConnectionService : IWebSocketConnectionService
{
    private readonly AuthDbContext _context;
    private readonly ILogger<WebSocketConnectionService> _logger;

    public WebSocketConnectionService(AuthDbContext context, ILogger<WebSocketConnectionService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null)
    {
        try
        {
            var application = await _context.Applications
              .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

            if (application == null)
            {
                _logger.LogWarning("Application not found for clientId: {ClientId}", clientId);
                return;
            }

            Guid? userGuid = null;
            if (!string.IsNullOrEmpty(userId) && Guid.TryParse(userId, out var parsedUserId))
            {
                userGuid = parsedUserId;
            }

            var existingConnection = await _context.WebSocketConnections
              .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

            if (existingConnection != null)
            {
                existingConnection.IsActive = true;
                existingConnection.ConnectedAt = DateTime.UtcNow;
                existingConnection.LastPingAt = DateTime.UtcNow;
                existingConnection.UserId = userGuid;
            }
            else
            {
                var connection = new WebSocketConnection
                {
                    ApplicationId = application.Id,
                    ConnectionId = connectionId,
                    UserId = userGuid,
                    ConnectedAt = DateTime.UtcNow,
                    LastPingAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.WebSocketConnections.Add(connection);
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("WebSocket connection registered: {ConnectionId} for app {ClientId} with user {UserId}",
              connectionId, clientId, userId ?? "anonymous");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error registering WebSocket connection {ConnectionId} for app {ClientId}",
              connectionId, clientId);
        }
    }

    public async Task UnregisterConnectionAsync(string connectionId)
    {
        try
        {
            var connection = await _context.WebSocketConnections
              .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

            if (connection != null)
            {
                connection.IsActive = false;
                connection.DisconnectedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                _logger.LogInformation("WebSocket connection unregistered: {ConnectionId}", connectionId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error unregistering WebSocket connection {ConnectionId}", connectionId);
        }
    }

    public async Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId)
    {
        try
        {
            var connections = await _context.WebSocketConnections
              .Join(_context.Applications, wc => wc.ApplicationId, a => a.Id, (wc, a) => new { wc, a })
              .Where(x => x.a.ClientId == clientId && x.wc.IsActive && x.a.IsActive && !x.a.IsDeleted)
              .Select(x => x.wc.ConnectionId)
              .ToListAsync();

            return connections;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active connections for application {ClientId}", clientId);
            return new List<string>();
        }
    }

    public async Task<bool> IsConnectionActiveAsync(string connectionId)
    {
        try
        {
            return await _context.WebSocketConnections
              .AnyAsync(c => c.ConnectionId == connectionId && c.IsActive);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if connection {ConnectionId} is active", connectionId);
            return false;
        }
    }

    public async Task UpdateLastPingAsync(string connectionId)
    {
        try
        {
            var connection = await _context.WebSocketConnections
              .FirstOrDefaultAsync(c => c.ConnectionId == connectionId);

            if (connection != null)
            {
                connection.LastPingAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating last ping for connection {ConnectionId}", connectionId);
        }
    }

    public async Task<int> GetActiveConnectionCountAsync(string clientId)
    {
        try
        {
            var count = await _context.WebSocketConnections
              .Join(_context.Applications, wc => wc.ApplicationId, a => a.Id, (wc, a) => new { wc, a })
              .Where(x => x.a.ClientId == clientId && x.wc.IsActive && x.a.IsActive && !x.a.IsDeleted)
              .CountAsync();

            return count;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active connection count for application {ClientId}", clientId);
            return 0;
        }
    }

    public async Task CleanupInactiveConnectionsAsync(int inactiveMinutes = 60)
    {
        try
        {
            var cutoffTime = DateTime.UtcNow.AddMinutes(-inactiveMinutes);

            var inactiveConnections = await _context.WebSocketConnections
              .Where(c => c.IsActive &&
                         (c.LastPingAt == null || c.LastPingAt < cutoffTime))
              .ToListAsync();

            foreach (var connection in inactiveConnections)
            {
                connection.IsActive = false;
                connection.DisconnectedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("Cleaned up {Count} inactive WebSocket connections", inactiveConnections.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up inactive WebSocket connections");
        }
    }
}
