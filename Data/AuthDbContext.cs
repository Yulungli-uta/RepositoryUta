using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Data.Configurations;

namespace WsSeguUta.AuthSystem.API.Data;
public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserEmployee> UserEmployees => Set<UserEmployee>();
    public DbSet<AppParam> AppParams => Set<AppParam>();
    public DbSet<LocalUserCredential> LocalUserCredentials => Set<LocalUserCredential>();
    public DbSet<SecurityToken> SecurityTokens => Set<SecurityToken>();
    public DbSet<PasswordHistory> PasswordHistory => Set<PasswordHistory>();
    public DbSet<UserAccountLock> UserAccountLocks => Set<UserAccountLock>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserRole> UserRoles => Set<UserRole>();
    public DbSet<MenuItem> MenuItems => Set<MenuItem>();
    public DbSet<RoleMenuItem> RoleMenuItems => Set<RoleMenuItem>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<FailedLoginAttempt> FailedLoginAttempts => Set<FailedLoginAttempt>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<LoginHistory> LoginHistory => Set<LoginHistory>();
    public DbSet<UserActivityLog> UserActivityLogs => Set<UserActivityLog>();
    public DbSet<RoleChangeHistory> RoleChangeHistory => Set<RoleChangeHistory>();
    public DbSet<PermissionChangeHistory> PermissionChangeHistory => Set<PermissionChangeHistory>();
    public DbSet<AzureSyncLog> AzureSyncLogs => Set<AzureSyncLog>();
    public DbSet<HRSyncLog> HRSyncLogs => Set<HRSyncLog>();
    
    // ========== ENTIDADES OPTIMIZADAS PARA CENTRALIZADOR ==========
    public DbSet<Application> Applications => Set<Application>();
    public DbSet<LegacyAuthLog> LegacyAuthLogs => Set<LegacyAuthLog>();
    public DbSet<NotificationSubscription> NotificationSubscriptions => Set<NotificationSubscription>();
    public DbSet<NotificationLog> NotificationLogs => Set<NotificationLog>();
    
    // ========== ENTIDADES PARA WEBSOCKETS HÍBRIDOS ==========
    public DbSet<WebSocketConnection> WebSocketConnections => Set<WebSocketConnection>();
    public DbSet<WebSocketMessage> WebSocketMessages => Set<WebSocketMessage>();
    public DbSet<WebSocketStats> WebSocketStats => Set<WebSocketStats>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new UserEmployeeConfiguration());
        modelBuilder.ApplyConfiguration(new AppParamConfiguration());
        modelBuilder.ApplyConfiguration(new LocalUserCredentialConfiguration());
        modelBuilder.ApplyConfiguration(new SecurityTokenConfiguration());
        modelBuilder.ApplyConfiguration(new PasswordHistoryConfiguration());
        modelBuilder.ApplyConfiguration(new UserAccountLockConfiguration());
        modelBuilder.ApplyConfiguration(new RoleConfiguration());
        modelBuilder.ApplyConfiguration(new PermissionConfiguration());
        modelBuilder.ApplyConfiguration(new RolePermissionConfiguration());
        modelBuilder.ApplyConfiguration(new UserRoleConfiguration());
        modelBuilder.ApplyConfiguration(new MenuItemConfiguration());
        modelBuilder.ApplyConfiguration(new RoleMenuItemConfiguration());
        modelBuilder.ApplyConfiguration(new UserSessionConfiguration());
        modelBuilder.ApplyConfiguration(new FailedLoginAttemptConfiguration());
        modelBuilder.ApplyConfiguration(new AuditLogConfiguration());
        modelBuilder.ApplyConfiguration(new LoginHistoryConfiguration());
        modelBuilder.ApplyConfiguration(new UserActivityLogConfiguration());
        modelBuilder.ApplyConfiguration(new RoleChangeHistoryConfiguration());
        modelBuilder.ApplyConfiguration(new PermissionChangeHistoryConfiguration());
        modelBuilder.ApplyConfiguration(new AzureSyncLogConfiguration());
        modelBuilder.ApplyConfiguration(new HRSyncLogConfiguration());


        modelBuilder.Entity<LocalUserCredential>(e =>
        {
            e.ToTable("tbl_LocalUserCredentials", "auth", tb =>
            {
                tb.HasTrigger("trg_LocalUserCredentials_Audit"); // informa a EF que hay trigger
                tb.UseSqlOutputClause(false);                    // desactiva OUTPUT para esta tabla
            });
        });

        base.OnModelCreating(modelBuilder);

    }
}
