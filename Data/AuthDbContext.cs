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
    
    // ========== APROVISIONAMIENTO DE EMPLEADOS ==========
    public DbSet<UserProvisioning> UserProvisionings => Set<UserProvisioning>();

    // ========== PERFILES DE ACCESO ==========
    public DbSet<AccessProfile> AccessProfiles => Set<AccessProfile>();
    public DbSet<AccessProfileRole> AccessProfileRoles => Set<AccessProfileRole>();
    public DbSet<UserAccessProfile> UserAccessProfiles => Set<UserAccessProfile>();

    // ========== VISTAS SQL ==========
    public DbSet<VwUserRole> VwUserRoles { get; set; }
    public DbSet<VwRoleMenuItem> VwRoleMenuItems { get; set; }
    public DbSet<VwActiveSession> VwActiveSessions { get; set; }
    public DbSet<VwActiveApiClient> VwActiveApiClients { get; set; }

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
        modelBuilder.ApplyConfiguration(new ApplicationConfiguration());
        modelBuilder.ApplyConfiguration(new NotificationSubscriptionConfiguration());
        modelBuilder.ApplyConfiguration(new NotificationLogConfiguration());
        modelBuilder.ApplyConfiguration(new WebSocketConnectionsConfiguration());
        modelBuilder.ApplyConfiguration(new UserProvisioningConfiguration());
        modelBuilder.ApplyConfiguration(new AccessProfileConfiguration());
        modelBuilder.ApplyConfiguration(new AccessProfileRoleConfiguration());
        modelBuilder.ApplyConfiguration(new UserAccessProfileConfiguration());

        modelBuilder.Entity<LocalUserCredential>(e =>
        {
            e.ToTable("tbl_LocalUserCredentials", "auth", tb =>
            {
                tb.HasTrigger("trg_LocalUserCredentials_Audit"); // informa a EF que hay trigger
                tb.UseSqlOutputClause(false);                    // desactiva OUTPUT para esta tabla
            });
        });
        
        // Configuración de vistas SQL
        modelBuilder.Entity<VwUserRole>().HasNoKey().ToView("vw_UserRoles", "auth");
        modelBuilder.Entity<VwRoleMenuItem>().HasNoKey().ToView("vw_RoleMenuItems", "auth");
        modelBuilder.Entity<VwActiveSession>().HasNoKey().ToView("vw_ActiveSessions", "auth");
        modelBuilder.Entity<VwActiveApiClient>().HasNoKey().ToView("vw_ActiveApiClients", "auth");

        // Soft-delete: cualquier entidad que implemente ISoftDeletable queda excluida
        // automáticamente de toda consulta EF Core normal (SELECT/paginación/Find) mientras
        // IsDeleted=true — sin tener que agregar el filtro manualmente en cada consulta.
        // GenericRepository<T>.DeleteAsync ya marca IsDeleted=true en vez de borrar la fila
        // cuando la entidad implementa esta interfaz (ver Data/Repositories/_Generic.cs).
        // No aplica a SQL/Dapper crudo — eso debe filtrar IsDeleted manualmente si lo usa.
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            if (!typeof(ISoftDeletable).IsAssignableFrom(entityType.ClrType)) continue;

            var parameter = System.Linq.Expressions.Expression.Parameter(entityType.ClrType, "e");
            var property = System.Linq.Expressions.Expression.Property(parameter, nameof(ISoftDeletable.IsDeleted));
            var notDeleted = System.Linq.Expressions.Expression.Not(property);
            var lambda = System.Linq.Expressions.Expression.Lambda(notDeleted, parameter);

            modelBuilder.Entity(entityType.ClrType).HasQueryFilter(lambda);
        }

        base.OnModelCreating(modelBuilder);

    }
}
