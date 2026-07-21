using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Models.Entities;

namespace WsSeguUta.AuthSystem.API.Data.Repositories;

public interface IUserRepository
{
    Task<User?> FindByEmailAsync(string email);
    Task<User?> FindByIdAsync(Guid id);
    Task<LocalUserCredential?> GetLocalCredAsync(Guid userId);
    Task UpdateLocalCredAsync(LocalUserCredential cred);
    Task SetLastLoginAsync(Guid userId, DateTime when);
    Task<string[]> GetRolesAsync(Guid userId);
    Task SyncAzureObjectIdAsync(Guid userId, Guid azureObjectId);
    Task<int?> GetHrEmployeeIdAsync(Guid userId);
    Task<string?> GetPersonnelEmailAsync(Guid userId);
}

public interface IAccessProfileAssignmentService
{
    /// <summary>Perfiles (activos) asignados actualmente a un usuario.</summary>
    Task<List<AccessProfile>> GetAssignedProfilesAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Asigna un AccessProfile a un usuario: crea/reactiva (vía IUserRoleService) una fila
    /// UserRole por cada rol que compone el perfil, marcando su origen (AssignedVia).
    /// Si el usuario ya tiene alguno de esos roles por otra vía, no lo duplica ni lo toca.
    /// </summary>
    Task AssignAsync(Guid userId, int accessProfileId, string? assignedBy, CancellationToken ct = default);

    /// <summary>
    /// Quita un AccessProfile de un usuario. Por cada rol del perfil, solo revoca el
    /// UserRole si ningún otro perfil activo del usuario ni una asignación directa lo
    /// justifican (evita romper accesos compartidos con otros perfiles).
    /// </summary>
    Task UnassignAsync(Guid userId, int accessProfileId, string? removedBy, CancellationToken ct = default);
}

public interface IAuthRepository
{
    Task<UserSession> CreateSessionAsync(Guid userId, string accessToken, string refreshHash, DateTime expiresAt, string? device, string? ip);
    Task<(UserSession Sess, User User)?> GetActiveSessionByRefreshHashAsync(string refreshHash);

    /// <summary>
    /// Busca una sesión INACTIVA cuyo refresh token (hash) fue rotado. Se usa para detectar
    /// reuso de refresh tokens: presentar un token ya rotado es el indicador más fiable de robo.
    /// </summary>
    Task<UserSession?> GetRotatedSessionByRefreshHashAsync(string refreshHash);

    /// <summary>
    /// Revoca en bloque todas las sesiones activas de un usuario (respuesta ante reuso
    /// de refresh token). Retorna la cantidad de sesiones revocadas.
    /// </summary>
    Task<int> RevokeAllActiveSessionsForUserAsync(Guid userId, string reason);

    Task RevokeSessionAsync(Guid sessionId, string reason);
    Task RecordFailedAttemptAsync(string email, string? ip, string? agent, string? reason);
    Task InsertLoginAsync(Guid? userId, string emailOrUser, bool ok, string type, string status, string? reason, Guid? sessionId, string? ip, string? agent, string? device);
}

public interface IRoleRepository { Task<IEnumerable<Role>> ListAsync(); }

public interface IMenuRepository { Task<IEnumerable<object>> GetMenuByUserAsync(Guid userId); }

public class UserRepository : IUserRepository
{
    private readonly AuthDbContext _db;
    public UserRepository(AuthDbContext db) => _db = db;

    public Task<User?> FindByEmailAsync(string email) => _db.Users.FirstOrDefaultAsync(u => u.Email == email);
    public Task<User?> FindByIdAsync(Guid id) => _db.Users.FirstOrDefaultAsync(u => u.Id == id);
    public Task<LocalUserCredential?> GetLocalCredAsync(Guid userId) => _db.LocalUserCredentials.FirstOrDefaultAsync(c => c.UserId == userId);
    public async Task UpdateLocalCredAsync(LocalUserCredential cred) { _db.LocalUserCredentials.Update(cred); await _db.SaveChangesAsync(); }
    public async Task SetLastLoginAsync(Guid userId, DateTime when) { var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == userId); if (u != null) { u.LastLogin = when; await _db.SaveChangesAsync(); } }
    public async Task SyncAzureObjectIdAsync(Guid userId, Guid azureObjectId) { var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == userId); if (u != null && u.AzureObjectId != azureObjectId) { u.AzureObjectId = azureObjectId; await _db.SaveChangesAsync(); } }
    public async Task<string[]> GetRolesAsync(Guid userId)
    {
        var q = from ur in _db.UserRoles
                join r in _db.Roles on ur.RoleId equals r.Id
                where ur.UserId == userId && !ur.IsDeleted && r.IsActive && !r.IsDeleted
                      && (ur.ExpiresAt == null || ur.ExpiresAt > DateTime.Now)
                select r.Name;
        return await q.ToArrayAsync();
    }

    public async Task<int?> GetHrEmployeeIdAsync(Guid userId)
    {
        return await _db.UserEmployees
            .Where(ue => ue.UserId == userId)
            .Select(ue => ue.HrEmployeeId)
            .FirstOrDefaultAsync();
    }

    public async Task<string?> GetPersonnelEmailAsync(Guid userId)
    {
        return await _db.UserEmployees
            .Where(ue => ue.UserId == userId && ue.IsActive)
            .Select(ue => ue.EmployeeEmail)
            .FirstOrDefaultAsync();
    }
}

public class AuthRepository : IAuthRepository
{
    private readonly AuthDbContext _db;
    public AuthRepository(AuthDbContext db) => _db = db;

    public async Task<UserSession> CreateSessionAsync(Guid userId, string accessToken, string refreshHash, DateTime expiresAt, string? device, string? ip)
    {
        var s = new UserSession { UserId = userId, AccessToken = accessToken, RefreshToken = refreshHash, ExpiresAt = expiresAt, DeviceInfo = device, IpAddress = ip, IsActive = true, Status="Active" };
        _db.UserSessions.Add(s); await _db.SaveChangesAsync(); return s;
    }

    public async Task<(UserSession Sess, User User)?> GetActiveSessionByRefreshHashAsync(string refreshHash)
    {
        var sess = await _db.UserSessions.FirstOrDefaultAsync(x => x.RefreshToken == refreshHash && x.IsActive && x.ExpiresAt > DateTime.Now);
        if (sess is null) return null;
        var u = await _db.Users.FirstOrDefaultAsync(x => x.Id == sess.UserId && x.IsActive);
        if (u is null) return null;
        return (sess, u);
    }

    public async Task<UserSession?> GetRotatedSessionByRefreshHashAsync(string refreshHash)
    {
        return await _db.UserSessions
            .FirstOrDefaultAsync(x => x.RefreshToken == refreshHash && !x.IsActive && x.Status == "Rotated");
    }

    public async Task<int> RevokeAllActiveSessionsForUserAsync(Guid userId, string reason)
    {
        // Usa el índice (UserId, IsActive, ExpiresAt); revoca en una sola sentencia sin cargar entidades
        return await _db.UserSessions
            .Where(x => x.UserId == userId && x.IsActive)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.IsActive, false)
                .SetProperty(x => x.Status, reason)
                .SetProperty(x => x.RevokedAt, DateTime.Now)
                .SetProperty(x => x.RevokedBy, "System"));
    }

    public async Task RevokeSessionAsync(Guid sessionId, string reason)
    {
        var s = await _db.UserSessions.FirstOrDefaultAsync(x => x.SessionId == sessionId);
        if (s is null) return;
        s.IsActive = false; s.Status = reason ?? "Revoked"; s.RevokedAt = DateTime.Now; await _db.SaveChangesAsync();
    }

    public async Task RecordFailedAttemptAsync(string email, string? ip, string? agent, string? reason)
    {
        _db.FailedLoginAttempts.Add(new FailedLoginAttempt { UserEmail = email, IpAddress = ip, UserAgent = agent, Reason = reason, AttemptedAt = DateTime.Now });
        await _db.SaveChangesAsync();
    }

    public async Task InsertLoginAsync(Guid? userId, string emailOrUser, bool ok, string type, string status, string? reason, Guid? sessionId, string? ip, string? agent, string? device)
    {
        
        _db.LoginHistory.Add(new LoginHistory {
          UserId = userId, LoginType = type, LoginStatus = status,
          FailureReason = reason, SessionId = sessionId, IpAddress = ip, UserAgent = agent, DeviceInfo = device,
          LoginDateTime = DateTime.Now //.Now
        });
        await _db.SaveChangesAsync();
    }
}

public class RoleRepository : IRoleRepository
{
    private readonly AuthDbContext _db;
    public RoleRepository(AuthDbContext db) => _db = db;
    public async Task<IEnumerable<Role>> ListAsync() => await _db.Roles.Where(r => !r.IsDeleted).OrderBy(r => r.Priority).ThenBy(r => r.Name).ToListAsync();
}

public class MenuRepository : IMenuRepository
{
    private readonly AuthDbContext _db;
    public MenuRepository(AuthDbContext db) => _db = db;
    private record MenuRow(int Id, int? ParentId, string name, string? url, string? Icon, //string SectionKey, string SectionTitle,
        int order);
    public async Task<IEnumerable<object>> GetMenuByUserAsync(Guid userId)
    {
        var uid = new SqlParameter("@UserId", userId);
        var rows = await _db.Database.SqlQueryRaw<MenuRow>("EXEC auth.sp_GetMenuByUser @UserId", uid).ToListAsync();
        return rows.Select(r => new { r.Id, r.ParentId, r.name, r.url, r.Icon, //r.SectionKey, r.SectionTitle, 
            r.order });
    }
}


// ========== NUEVO REPOSITORIO PARA AZURE AD MANAGEMENT ==========

public interface IAzureAdRepository
{
    Task<User?> FindByAzureIdAsync(Guid azureObjectId);
    Task<User> CreateOrUpdateFromAzureAsync(string azureObjectId, string email, string displayName);
    Task LogAzureSyncAsync(string syncType, int processed, int created, int updated, int errors, string details);
}

public class AzureAdRepository : IAzureAdRepository
{
    private readonly AuthDbContext _db;
    public AzureAdRepository(AuthDbContext db) => _db = db;
    
    public Task<User?> FindByAzureIdAsync(Guid azureObjectId) 
        => _db.Users.FirstOrDefaultAsync(u => u.AzureObjectId == azureObjectId);
    
    public async Task<User> CreateOrUpdateFromAzureAsync(string azureObjectId, string email, string displayName)
    {
        var user = await FindByAzureIdAsync(Guid.Parse(azureObjectId));
        
        if (user == null)
        {
            // Crear nuevo usuario local vinculado a Azure
            user = new User
            {
                Id = Guid.NewGuid(),
                Email = email,
                DisplayName = displayName,
                AzureObjectId = Guid.Parse(azureObjectId),
                UserType = "AzureAD",
                IsActive = true,
                CreatedAt = DateTime.Now
            };
            _db.Users.Add(user);
        }
        else
        {
            // Actualizar usuario existente
            user.Email = email;
            user.DisplayName = displayName;
            user.IsActive = true;
            _db.Users.Update(user);
        }
        
        await _db.SaveChangesAsync();
        return user;
    }
    
    public async Task LogAzureSyncAsync(string syncType, int processed, int created, int updated, int errors, string details)
    {
        await _db.AzureSyncLogs.AddAsync(new AzureSyncLog
        {
            SyncType = syncType,
            SyncDate = DateTime.Now,
            RecordsProcessed = processed,
            NewUsers = created,
            UpdatedUsers = updated,
            Errors = errors,
            Details = details
        });
        await _db.SaveChangesAsync();
    }
}
