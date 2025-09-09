using System.Security.Cryptography;
using AutoMapper;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using System.Net.Http.Headers;
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
  }

  public class AzureAuthService : IAzureAuthService
  {
    private readonly IConfiguration _cfg; private readonly IHttpClientFactory _http; private readonly IUserRepository _users; private readonly ITokenService _tokens; private readonly IAuthRepository _auth; private readonly IMemoryCache _cache;
    public AzureAuthService(IConfiguration cfg, IHttpClientFactory http, IUserRepository users, ITokenService tokens, IAuthRepository auth, IMemoryCache cache){ _cfg=cfg; _http=http; _users=users; _tokens=tokens; _auth=auth; _cache=cache; }

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
      if (user is null) return null; // aquÃ­ puedes auto-provisionar si deseas
      var roles = await _users.GetRolesAsync(user.Id);
      var access = _tokens.Create(user.Id, email, roles);
      var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
      var refreshHash = _tokens.Hash(refresh);
      var exp = DateTime.UtcNow.AddDays(7);
      await _auth.CreateSessionAsync(user.Id, access, refreshHash, exp, null, null);
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
