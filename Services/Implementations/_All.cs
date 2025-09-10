using System.Security.Cryptography;
using AutoMapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Security;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Utilities;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
  public class TokenService : ITokenService
  {
    private readonly JwtTokenService _jwt; public TokenService(JwtTokenService jwt)=>_jwt=jwt;
    public string Create(Guid userId,string email,IEnumerable<string> roles)=>_jwt.Create(userId,email,roles);
    public string Hash(string input)=>Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input)));
  }

  public class AuthService : IAuthService
  {
    private readonly IUserRepository _users; private readonly IAuthRepository _auth; private readonly ITokenService _tokens;

    public AuthService(IUserRepository users,IAuthRepository auth,ITokenService tokens)
    { _users=users; _auth=auth; _tokens=tokens; }

    public async Task<TokenPair?> LoginLocalAsync(string email,string password)
    {
      var now = DateTime.UtcNow;
      var u = await _users.FindByEmailAsync(email);
      if (u is null || !u.IsActive || !string.Equals(u.UserType, "Local", StringComparison.OrdinalIgnoreCase))
      { await _auth.RecordFailedAttemptAsync(email, null, null, "User not found/inactive"); await _auth.InsertLoginAsync(null, email, false, "Local", "Failed", "User not found/inactive", null, null, null, null); return null; }

      var cred = await _users.GetLocalCredAsync(u.Id);
      if (cred is null)
      { await _auth.RecordFailedAttemptAsync(email, null, null, "No credentials"); await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "No credentials", null, null, null, null); return null; }

      if (cred.IsLocked || (cred.LockedUntil.HasValue && cred.LockedUntil.Value > now))
      { await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Blocked", "Locked account", null, null, null, null); return null; }

      if (cred.PasswordExpiresAt.HasValue && cred.PasswordExpiresAt.Value <= now)
      { await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "Password expired", null, null, null, null); return null; }
      //Console.WriteLine($"Verifying password AuthService-LoginLocalAsync - for {email}, password: {password}");
      var ok = PasswordHasher.Verify(password, cred.PasswordHash);
      if (!ok)
      {
        cred.FailedAttempts += 1; cred.LastFailedAttempt = now;
        if (cred.FailedAttempts >= 5){ cred.LockedUntil = now.AddMinutes(30); cred.IsLocked = true; }
        await _users.UpdateLocalCredAsync(cred);
        await _auth.RecordFailedAttemptAsync(email, null, null, "Invalid password");
        await _auth.InsertLoginAsync(u.Id, email, false, "Local", cred.IsLocked ? "Blocked" : "Failed", "Invalid password", null, null, null, null);
        return null;
      }

      cred.FailedAttempts = 0; cred.IsLocked = false; cred.LockedUntil = null; await _users.UpdateLocalCredAsync(cred);
      //Console.WriteLine($"paso la verificacion -**************** --- *Password verified for {email}");
      var roles = await _users.GetRolesAsync(u.Id);
      //Console.WriteLine($"Roles for {email}: {string.Join(",", roles)}");
      var access = _tokens.Create(u.Id, u.Email, roles);
      Console.WriteLine($"Access token created for {email}: {access}");
      var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
      //Console.WriteLine($"Refresh token created for {email}: {refresh}");
      var refreshHash = _tokens.Hash(refresh);
      //Console.WriteLine($"Refresh token hash for {email}: {refreshHash}");
      var expiresAt = now.AddDays(7);
      //Console.WriteLine($"Creating session for {email}, expires at {expiresAt}");
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
        // Intentar parsear como GUID (token de sesión)
        if (Guid.TryParse(token, out var tokenGuid))
        {
          var session = await _auth.GetActiveSessionAsync(tokenGuid);
          if (session != null)
          {
            return new ValidateTokenResponse(true, "User token", session.ExpiresAt, session.UserId, session.SessionId, "Token is valid");
          }
        }

        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired");
      }
      catch (Exception)
      {
        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Error validating token");
      }
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
      _cfg=cfg; 
      _http=http; 
      _users=users; 
      _tokens=tokens; 
      _auth=auth; 
      _cache=cache; 
      _notificationService=notificationService;
    }

    public async Task<(string Url,string State)> BuildAuthUrlAsync()
    {
      var tenant=_cfg["AzureAd:TenantId"]; var clientId=_cfg["AzureAd:ClientId"]; var authority=$"https://login.microsoftonline.com/{tenant}/v2.0"; var redirect=_cfg["AzureAd:RedirectUri"]!;
      var cca=ConfidentialClientApplicationBuilder.Create(clientId).WithAuthority(authority).WithClientSecret(_cfg["AzureAd:ClientSecret"]).WithRedirectUri(redirect).Build();
      var scopes = new[] { "openid","profile","email","offline_access","User.Read" };
      var state=Guid.NewGuid().ToString("N"); _cache.Set($"ms_state:{state}", true, TimeSpan.FromMinutes(10));
            //var url=await cca.GetAuthorizationRequestUrl(scopes).WithRedirectUri(redirect).WithState(state).ExecuteAsync();
            var url = await cca.GetAuthorizationRequestUrl(scopes).WithRedirectUri(redirect).WithExtraQueryParameters(new Dictionary<string, string> { { "state", state } }).ExecuteAsync();
            return (url.ToString(), state);
    }

    public async Task<TokenPair?> HandleCallbackAsync(string code,string state)
    {
      if(!_cache.TryGetValue($"ms_state:{state}", out _)) return null;
      var tenant=_cfg["AzureAd:TenantId"]; var clientId=_cfg["AzureAd:ClientId"]; var authority=$"https://login.microsoftonline.com/{tenant}/v2.0"; var redirect=_cfg["AzureAd:RedirectUri"]!;
      var cca=ConfidentialClientApplicationBuilder.Create(clientId).WithAuthority(authority).WithClientSecret(_cfg["AzureAd:ClientSecret"]).WithRedirectUri(redirect).Build();
      var scopes=new[]{"openid","profile","email","offline_access","User.Read"};
      var result=await cca.AcquireTokenByAuthorizationCode(scopes, code).ExecuteAsync();

      var client=_http.CreateClient(); client.DefaultRequestHeaders.Authorization=new AuthenticationHeaderValue("Bearer", result.AccessToken);
      var res=await client.GetAsync("https://graph.microsoft.com/v1.0/me"); res.EnsureSuccessStatusCode();
      var json = await res.Content.ReadAsStringAsync();
      var email = System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("userPrincipalName").GetString() ?? "";

      var user = await _users.FindByEmailAsync(email);
      if (user is null) return null; // aquí puedes auto-provisionar si deseas
      
      var roles = await _users.GetRolesAsync(user.Id);
      var access = _tokens.Create(user.Id, email, roles);
      var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
      var refreshHash = _tokens.Hash(refresh);
      var exp = DateTime.UtcNow.AddDays(7);
      var session = await _auth.CreateSessionAsync(user.Id, access, refreshHash, exp, null, null);
      
      // ========== NOTIFICAR LOGIN CON OFFICE365 ==========
      // NOTA: Las notificaciones ahora se manejan en el AuthController
      // para tener acceso a la IP del cliente y otros datos del request
      
      return new TokenPair(access, refresh);
    }
  }

  public class MenuService : IMenuService
  {
    private readonly IMenuRepository _repo; public MenuService(IMenuRepository repo)=>_repo=repo;
    public Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId)=>_repo.GetMenuByUserAsync(userId);
  }

  // CRUD GenÃ©rico
  public class CrudService<TEntity, TCreate, TUpdate> : ICrudService<TEntity, TCreate, TUpdate> where TEntity: class, new()
  {
    private readonly IGenericRepository<TEntity> _repo; private readonly IMapper _map;
    public CrudService(IGenericRepository<TEntity> repo, IMapper map){ _repo=repo; _map=map; }
    public Task<IEnumerable<TEntity>> ListAsync(int page,int size)=>_repo.GetAllAsync(page,size);
    public Task<TEntity?> GetAsync(params object[] key)=>_repo.GetAsync(key);
    public async Task<TEntity> CreateAsync(TCreate dto){ var e=_map.Map<TEntity>(dto); return await _repo.AddAsync(e); }
    public async Task<TEntity?> UpdateAsync(object key, TUpdate dto){ var current = await _repo.GetAsync(key); if (current==null) return null; _map.Map(dto, current); return await _repo.UpdateAsync(current); }
    public Task<bool> DeleteAsync(params object[] key)=>_repo.DeleteAsync(key);
  }
}

  // ========== IMPLEMENTACIÓN DEL SERVICIO CENTRALIZADOR ==========
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
        // Buscar aplicación por ClientId
        var app = await _context.Applications
          .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

        if (app == null)
        {
          _logger.LogWarning("Application not found or inactive: {ClientId}", clientId);
          return new AppAuthResponse(false, "Invalid client credentials", null, null, null);
        }

        // Verificar el secreto (en producción usar bcrypt)
        var providedSecretHash = _tokenService.Hash(clientSecret);
        if (app.ClientSecretHash != providedSecretHash)
        {
          _logger.LogWarning("Invalid client secret for application: {ClientId}", clientId);
          return new AppAuthResponse(false, "Invalid client credentials", null, null, null);
        }

        // Crear token de aplicación
        var tokenId = Guid.NewGuid();
        var expiresAt = DateTime.UtcNow.AddMinutes(app.TokenExpirationMin);
        var tokenHash = _tokenService.Hash(tokenId.ToString());

        var appToken = new ApplicationToken
        {
          Id = tokenId,
          ApplicationId = app.Id,
          TokenHash = tokenHash,
          ExpiresAt = expiresAt,
          IpAddress = ipAddress,
          UserAgent = userAgent
        };

        _context.ApplicationTokens.Add(appToken);
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
        // Verificar aplicación
        var app = await _context.Applications
          .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

        if (app == null)
        {
          failureReason = "Invalid application";
          goto LogAndReturn;
        }

        applicationId = app.Id;

        // Verificar secreto de aplicación
        var providedSecretHash = _tokenService.Hash(clientSecret);
        if (app.ClientSecretHash != providedSecretHash)
        {
          failureReason = "Invalid application credentials";
          goto LogAndReturn;
        }

        // Buscar usuario
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

        // Verificar credenciales según tipo de usuario
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

          // Verificar contraseña (en producción usar bcrypt)
          var providedPasswordHash = _tokenService.Hash(password);
          if (credentials.PasswordHash != providedPasswordHash)
          {
            // Incrementar intentos fallidos
            credentials.FailedAttempts++;
            credentials.LastFailedAttempt = DateTime.UtcNow;
            
            // Bloquear si excede intentos máximos
            var maxAttempts = 5; // Debería venir de configuración
            if (credentials.FailedAttempts >= maxAttempts)
            {
              credentials.IsLocked = true;
            }

            await _context.SaveChangesAsync();
            failureReason = "Invalid password";
            goto LogAndReturn;
          }

          // Resetear intentos fallidos en login exitoso
          credentials.FailedAttempts = 0;
          credentials.LastFailedAttempt = null;
          await _context.SaveChangesAsync();
        }
        else if (user.UserType == "AzureAD")
        {
          // Para usuarios de Azure AD, aquí se validaría contra Azure
          // Por ahora, rechazamos la autenticación local para usuarios de Azure
          failureReason = "Azure AD users must authenticate through Azure";
          goto LogAndReturn;
        }

        // Actualizar último login
        user.LastLogin = DateTime.UtcNow;
        await _context.SaveChangesAsync();

        authResult = "Success";

        // Preparar respuesta exitosa
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

        // Incluir roles y permisos si se solicita
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
            .Join(_context.Permissions, rp => rp.PermissionId, p => p.Id, (rp, p) => new { p.Id, p.Name, p.Module, p.Action, p.Description })
            .Where(p => !p.IsDeleted)
            .Distinct()
            .ToListAsync();

          response = response with { Roles = roles, Permissions = permissions };
        }

        // Registrar log exitoso
        await LogAuthAttempt(applicationId.Value, userId, userEmail, authResult, failureReason, ipAddress, userAgent, startTime);

        return response;

        LogAndReturn:
        // Registrar log fallido
        await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, authResult, failureReason, ipAddress, userAgent, startTime);

        return new LegacyAuthResponse(false, failureReason ?? "Authentication failed", null, null, null, null, null, null);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error during legacy authentication for user: {Email}", userEmail);
        
        // Registrar log de error
        await LogAuthAttempt(applicationId ?? Guid.Empty, userId, userEmail, "Error", ex.Message, ipAddress, userAgent, startTime);
        
        return new LegacyAuthResponse(false, "Internal server error", null, null, null, null, null, null);
      }
    }

    public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId)
    {
      try
      {
        // Intentar parsear como GUID (token de aplicación o sesión)
        if (Guid.TryParse(token, out var tokenGuid))
        {
          // Verificar si es token de aplicación
          if (!string.IsNullOrEmpty(clientId))
          {
            var app = await _context.Applications
              .FirstOrDefaultAsync(a => a.ClientId == clientId && a.IsActive && !a.IsDeleted);

            if (app != null)
            {
              var appToken = await _context.ApplicationTokens
                .FirstOrDefaultAsync(t => t.Id == tokenGuid && t.ApplicationId == app.Id && t.IsActive);

              if (appToken != null && appToken.ExpiresAt > DateTime.UtcNow)
              {
                return new ValidateTokenResponse(true, "Application token", appToken.ExpiresAt, null, null, "Token is valid");
              }
            }
          }

          // Verificar si es token de sesión de usuario
          var userSession = await _context.UserSessions
            .FirstOrDefaultAsync(s => s.SessionId == tokenGuid && s.IsActive);

          if (userSession != null && userSession.ExpiresAt > DateTime.UtcNow)
          {
            return new ValidateTokenResponse(true, "User token", userSession.ExpiresAt, userSession.UserId, userSession.SessionId, "Token is valid");
          }
        }

        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired");
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error validating token");
        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Error validating token");
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
          ActiveTokens = await _context.ApplicationTokens.CountAsync(t => t.ApplicationId == app.Id && t.IsActive && t.ExpiresAt > DateTime.UtcNow)
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

    public NotificationService(AuthDbContext context, IHttpClientFactory httpClientFactory, ILogger<NotificationService> logger, IConfiguration configuration)
    {
      _context = context;
      _httpClientFactory = httpClientFactory;
      _logger = logger;
      _configuration = configuration;
    }

    public async Task<Guid> CreateSubscriptionAsync(Guid applicationId, string eventType, string webhookUrl, string? secretKey)
    {
      try
      {
        // Verificar que la aplicación existe
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

    public async Task NotifyLoginEventAsync(Guid userId, string loginType, string? ipAddress, object? roles, object? permissions)
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
          permissions
        );

        await CreateNotificationEventAsync(userId, null, "Login", eventData);
        _logger.LogInformation("Login notification event created for user {UserId}", userId);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error creating login notification for user {UserId}", userId);
      }
    }

    public async Task NotifyLogoutEventAsync(Guid userId)
    {
      try
      {
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return;

        var eventData = new LogoutEventData(userId, user.Email, DateTime.UtcNow);
        await CreateNotificationEventAsync(userId, null, "Logout", eventData);
        _logger.LogInformation("Logout notification event created for user {UserId}", userId);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error creating logout notification for user {UserId}", userId);
      }
    }

    public async Task NotifyUserCreatedEventAsync(Guid userId)
    {
      try
      {
        var user = await _context.Users.FindAsync(userId);
        if (user == null) return;

        var eventData = new UserCreatedEventData(userId, user.Email, user.DisplayName ?? "", user.UserType, user.CreatedAt);
        await CreateNotificationEventAsync(userId, null, "UserCreated", eventData);
        _logger.LogInformation("User created notification event created for user {UserId}", userId);
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error creating user created notification for user {UserId}", userId);
      }
    }

    public async Task<NotificationStatsDto> GetNotificationStatsAsync()
    {
      var totalSubscriptions = await _context.NotificationSubscriptions.CountAsync();
      var activeSubscriptions = await _context.NotificationSubscriptions.CountAsync(s => s.IsActive);
      var totalEvents = await _context.NotificationEvents.CountAsync();
      var pendingEvents = await _context.NotificationEvents.CountAsync(e => !e.IsProcessed);
      var failedNotifications = await _context.NotificationLogs.CountAsync(l => !l.IsSuccess);

      return new NotificationStatsDto(totalSubscriptions, activeSubscriptions, totalEvents, pendingEvents, failedNotifications);
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
          s.LastNotified
        ))
        .ToListAsync();

      return subscriptions;
    }

    public async Task ProcessPendingNotificationsAsync()
    {
      try
      {
        var pendingEvents = await _context.NotificationEvents
          .Where(e => !e.IsProcessed && e.RetryCount < 3)
          .OrderBy(e => e.CreatedAt)
          .Take(50) // Procesar máximo 50 eventos por vez
          .ToListAsync();

        foreach (var eventItem in pendingEvents)
        {
          await ProcessNotificationEventAsync(eventItem);
        }
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error processing pending notifications");
      }
    }

    private async Task CreateNotificationEventAsync(Guid? userId, Guid? applicationId, string eventType, object eventData)
    {
      var notificationEvent = new NotificationEvent
      {
        UserId = userId,
        ApplicationId = applicationId,
        EventType = eventType,
        EventData = System.Text.Json.JsonSerializer.Serialize(eventData)
      };

      _context.NotificationEvents.Add(notificationEvent);
      await _context.SaveChangesAsync();

      // Procesar inmediatamente en background
      _ = Task.Run(() => ProcessNotificationEventAsync(notificationEvent));
    }

    private async Task ProcessNotificationEventAsync(NotificationEvent eventItem)
    {
      try
      {
        // Obtener suscripciones activas para este tipo de evento
        var subscriptions = await _context.NotificationSubscriptions
          .Where(s => s.EventType == eventItem.EventType && s.IsActive)
          .ToListAsync();

        foreach (var subscription in subscriptions)
        {
          await SendWebhookNotificationAsync(subscription, eventItem);
        }

        // Marcar evento como procesado
        eventItem.IsProcessed = true;
        eventItem.ProcessedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
      }
      catch (Exception ex)
      {
        _logger.LogError(ex, "Error processing notification event {EventId}", eventItem.Id);
        
        // Incrementar contador de reintentos
        eventItem.RetryCount++;
        eventItem.LastError = ex.Message;
        await _context.SaveChangesAsync();
      }
    }

    private async Task SendWebhookNotificationAsync(NotificationSubscription subscription, NotificationEvent eventItem)
    {
      var startTime = DateTime.UtcNow;
      var httpClient = _httpClientFactory.CreateClient();
      
      try
      {
        // Crear payload del webhook
        var payload = new WebhookPayload(
          eventItem.EventType,
          eventItem.CreatedAt,
          System.Text.Json.JsonSerializer.Deserialize<object>(eventItem.EventData) ?? new { },
          GenerateSignature(eventItem.EventData, subscription.SecretKey)
        );

        var jsonPayload = System.Text.Json.JsonSerializer.Serialize(payload);
        var content = new StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");

        // Configurar headers
        httpClient.Timeout = TimeSpan.FromSeconds(30);
        if (!string.IsNullOrEmpty(subscription.SecretKey))
        {
          content.Headers.Add("X-Webhook-Signature", payload.Signature);
        }

        // Enviar webhook
        var response = await httpClient.PostAsync(subscription.WebhookUrl, content);
        var responseBody = await response.Content.ReadAsStringAsync();
        var responseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;

        // Registrar log
        var log = new NotificationLog
        {
          SubscriptionId = subscription.Id,
          EventId = eventItem.Id,
          WebhookUrl = subscription.WebhookUrl,
          RequestPayload = jsonPayload,
          ResponseStatusCode = (int)response.StatusCode,
          ResponseBody = responseBody,
          IsSuccess = response.IsSuccessStatusCode,
          ResponseTimeMs = responseTime,
          ErrorMessage = response.IsSuccessStatusCode ? null : $"HTTP {response.StatusCode}: {responseBody}"
        };

        _context.NotificationLogs.Add(log);

        // Actualizar estadísticas de suscripción
        if (response.IsSuccessStatusCode)
        {
          subscription.LastNotified = DateTime.UtcNow;
          subscription.FailureCount = 0;
        }
        else
        {
          subscription.FailureCount++;
          subscription.LastFailure = DateTime.UtcNow;
          subscription.LastError = log.ErrorMessage;
        }

        await _context.SaveChangesAsync();

        _logger.LogInformation("Webhook sent to {WebhookUrl} with status {StatusCode}", subscription.WebhookUrl, response.StatusCode);
      }
      catch (Exception ex)
      {
        var responseTime = (int)(DateTime.UtcNow - startTime).TotalMilliseconds;
        
        // Registrar log de error
        var errorLog = new NotificationLog
        {
          SubscriptionId = subscription.Id,
          EventId = eventItem.Id,
          WebhookUrl = subscription.WebhookUrl,
          RequestPayload = System.Text.Json.JsonSerializer.Serialize(new { eventItem.EventType, eventItem.EventData }),
          ResponseStatusCode = 0,
          IsSuccess = false,
          ResponseTimeMs = responseTime,
          ErrorMessage = ex.Message
        };

        _context.NotificationLogs.Add(errorLog);

        // Actualizar estadísticas de suscripción
        subscription.FailureCount++;
        subscription.LastFailure = DateTime.UtcNow;
        subscription.LastError = ex.Message;

        await _context.SaveChangesAsync();

        _logger.LogError(ex, "Error sending webhook to {WebhookUrl}", subscription.WebhookUrl);
      }
    }

    private string GenerateSignature(string payload, string? secretKey)
    {
      if (string.IsNullOrEmpty(secretKey)) return "";

      using var hmac = new System.Security.Cryptography.HMACSHA256(System.Text.Encoding.UTF8.GetBytes(secretKey));
      var hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(payload));
      return Convert.ToHexString(hash).ToLower();
    }
  }

