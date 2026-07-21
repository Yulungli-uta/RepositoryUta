namespace WsSeguUta.AuthSystem.API.Models.Entities;

public class User : ISoftDeletable { public Guid Id { get; set; } public string Email { get; set; } = string.Empty; public string? DisplayName { get; set; } public Guid? AzureObjectId { get; set; } public bool IsActive { get; set; } = true; public DateTime CreatedAt { get; set; } = DateTime.Now; public DateTime? LastLogin { get; set; } public string UserType { get; set; } = "AzureAD"; public bool IsDeleted { get; set; } = false; }
public class UserEmployee { public int Id { get; set; } public Guid UserId { get; set; } public string EmployeeEmail { get; set; } = string.Empty; public int? HrEmployeeId { get; set; } public bool IsActive { get; set; } = true; public DateTime? SyncDate { get; set; } public string? Notes { get; set; } }
public class AppParam { public string Nemonic { get; set; } = string.Empty; public string Value { get; set; } = string.Empty; public string DataType { get; set; } = "string"; public string Category { get; set; } = "General"; public string? Description { get; set; } public bool IsEncrypted { get; set; } = false; public DateTime LastModified { get; set; } = DateTime.Now; public string? ModifiedBy { get; set; } }
public class LocalUserCredential { public Guid UserId { get; set; } public string PasswordHash { get; set; } = string.Empty; public DateTime PasswordCreatedAt { get; set; } = DateTime.Now; public DateTime? PasswordExpiresAt { get; set; } public bool MustChangePassword { get; set; } = false; public int FailedAttempts { get; set; } = 0; public DateTime? LastFailedAttempt { get; set; } public DateTime? LockedUntil { get; set; } public bool IsLocked { get; set; } = false; public bool TwoFactorEnabled { get; set; } = false; public string? TwoFactorSecret { get; set; } public string? SecurityQuestions { get; set; } }
public class SecurityToken { public Guid Id { get; set; } = Guid.NewGuid(); public Guid UserId { get; set; } public string TokenType { get; set; } = "PasswordReset"; public string TokenHash { get; set; } = string.Empty; public DateTime ExpiresAt { get; set; } public bool IsUsed { get; set; } = false; public DateTime CreatedAt { get; set; } = DateTime.Now; public string? AdditionalData { get; set; } }
public class PasswordHistory { public long Id { get; set; } public Guid UserId { get; set; } public string PasswordHash { get; set; } = string.Empty; public DateTime CreatedAt { get; set; } = DateTime.Now; }
public class UserAccountLock { public long Id { get; set; } public Guid UserId { get; set; } public string LockType { get; set; } = "FailedAttempts"; public string LockReason { get; set; } = string.Empty; public DateTime LockedAt { get; set; } = DateTime.Now; public string? LockedBy { get; set; } public DateTime? AutoUnlockAt { get; set; } public DateTime? UnlockedAt { get; set; } public string? UnlockedBy { get; set; } public bool IsActive { get; set; } = true; }
public class Role : ISoftDeletable { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string? Description { get; set; } public bool IsActive { get; set; } = true; public int Priority { get; set; } = 100; public DateTime CreatedAt { get; set; } = DateTime.Now; public bool IsDeleted { get; set; } = false; }
public class Permission : ISoftDeletable { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string Module { get; set; } = string.Empty; public string Action { get; set; } = "Read"; public string? Description { get; set; } public int Version { get; set; } = 1; public bool IsDeleted { get; set; } = false; }
public class RolePermission { public int RoleId { get; set; } public int PermissionId { get; set; } public DateTime GrantedAt { get; set; } = DateTime.Now; public string? GrantedBy { get; set; } }
public class UserRole { public Guid UserId { get; set; } public int RoleId { get; set; } public DateTime AssignedAt { get; set; } = DateTime.Now; public DateTime? ExpiresAt { get; set; } public string? AssignedBy { get; set; } public string? Reason { get; set; } public bool IsDeleted { get; set; } = false; /* Origen de la asignación: null/"Direct" = directo, "Profile:{AccessProfileId}" = heredado de un perfil de acceso. */ public string? AssignedVia { get; set; } }
public class MenuItem : ISoftDeletable { public int Id { get; set; } public string Name { get; set; } = string.Empty; public string? Url { get; set; } public string? Icon { get; set; } public int? ParentId { get; set; } public int Order { get; set; } = 0; public bool IsVisible { get; set; } = true; public string? ModuleName { get; set; } public bool IsDeleted { get; set; } = false; }
public class RoleMenuItem { public int RoleId { get; set; } public int MenuItemId { get; set; } public bool IsVisible { get; set; } = true; }
public class UserSession { public Guid SessionId { get; set; } = Guid.NewGuid(); public Guid UserId { get; set; } public string AccessToken { get; set; } = string.Empty; public string RefreshToken { get; set; } = string.Empty; public DateTime ExpiresAt { get; set; } public bool IsActive { get; set; } = true; public string? DeviceInfo { get; set; } public string? IpAddress { get; set; } public DateTime CreatedAt { get; set; } = DateTime.Now; public string Status { get; set; } = "Active"; public string? BrowserId { get; set; } public string? UserAgent { get; set; } public DateTime? LastActivityAt { get; set; } public DateTime? RevokedAt { get; set; } public string? RevokedBy { get; set; } }
public class FailedLoginAttempt { public long Id { get; set; } public string UserEmail { get; set; } = string.Empty; public DateTime AttemptedAt { get; set; } = DateTime.Now; public string? IpAddress { get; set; } public string? UserAgent { get; set; } public string? Reason { get; set; } public DateTime? WindowBucket { get; set; } }
public class AuditLog { public long Id { get; set; } public Guid? UserId { get; set; } public string Action { get; set; } = string.Empty; public string Module { get; set; } = string.Empty; public string? EntityId { get; set; } public string? OldValues { get; set; } public string? NewValues { get; set; } public string? IpAddress { get; set; } public string? UserAgent { get; set; } public DateTime Timestamp { get; set; } = DateTime.Now; }
public class LoginHistory { public long Id { get; set; } public Guid? UserId { get; set; } public DateTime LoginDateTime { get; set; } = DateTime.Now; public string LoginType { get; set; } = "Local"; public string? IpAddress { get; set; } public string? UserAgent { get; set; } public string? DeviceInfo { get; set; } public string? LocationInfo { get; set; } public string LoginStatus { get; set; } = "Success"; public string? FailureReason { get; set; } public Guid? SessionId { get; set; } }
public class UserActivityLog { public long Id { get; set; } public Guid UserId { get; set; } public Guid? SessionId { get; set; } public string Activity { get; set; } = string.Empty; public string? ActivityDetails { get; set; } public string? IpAddress { get; set; } public string? UserAgent { get; set; } public DateTime Timestamp { get; set; } = DateTime.Now; public string? ModuleAccessed { get; set; } public string? ActionPerformed { get; set; } }
public class RoleChangeHistory { public long Id { get; set; } public Guid UserId { get; set; } public int RoleId { get; set; } public string ChangeType { get; set; } = "Assigned"; public string ChangedBy { get; set; } = string.Empty; public string? ChangeReason { get; set; } public string? PreviousValue { get; set; } public string? NewValue { get; set; } public DateTime? EffectiveFrom { get; set; } public DateTime? EffectiveTo { get; set; } public DateTime ChangeDateTime { get; set; } = DateTime.Now; public bool ApprovalRequired { get; set; } = false; public string? ApprovedBy { get; set; } public DateTime? ApprovalDateTime { get; set; } }
public class PermissionChangeHistory { public long Id { get; set; } public int RoleId { get; set; } public int PermissionId { get; set; } public string ChangeType { get; set; } = "Added"; public string ChangedBy { get; set; } = string.Empty; public string? ChangeReason { get; set; } public DateTime ChangeDateTime { get; set; } = DateTime.Now; public int AffectedUsersCount { get; set; } = 0; }
public class AzureSyncLog { public long Id { get; set; } public DateTime SyncDate { get; set; } = DateTime.Now; public int RecordsProcessed { get; set; } = 0; public int NewUsers { get; set; } = 0; public int UpdatedUsers { get; set; } = 0; public int Errors { get; set; } = 0; public string? Details { get; set; } public string SyncType { get; set; } = "Auto"; }
public class HRSyncLog { public long Id { get; set; } public DateTime SyncDate { get; set; } = DateTime.Now; public int RecordsProcessed { get; set; } = 0; public int NewUsers { get; set; } = 0; public int UpdatedUsers { get; set; } = 0; public int Errors { get; set; } = 0; public string? Details { get; set; } public string SyncType { get; set; } = "Auto"; }


// ========== NUEVAS ENTIDADES PARA CENTRALIZADOR DE AUTENTICACIÓN ==========

public class Application
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecretHash { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public string? CreatedBy { get; set; }
    public DateTime? ModifiedAt { get; set; } = DateTime.Now;
    public string? ModifiedBy { get; set; }
    public bool IsDeleted { get; set; } = false;
    public DateTime? LastUsedAt { get; set; }
    public DateTime? SecretRotatedAt { get; set; }
    public string? SecretRotatedBy { get; set; }
    public DateTime? SuspendedAt { get; set; }
    public string? SuspendedBy { get; set; }
}

public class LegacyAuthLog 
{ 
    public long Id { get; set; } 
    public Guid ApplicationId { get; set; } 
    public Guid? UserId { get; set; } 
    public string UserEmail { get; set; } = string.Empty; 
    public string AuthResult { get; set; } = string.Empty; 
    public string AuthType { get; set; } = string.Empty; // "Local", "Office365", "Legacy"
    public string? FailureReason { get; set; } 
    public string? IpAddress { get; set; } 
    public string? UserAgent { get; set; } 
    public int? ResponseTime { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.Now; 
}

// ========== ENTIDADES OPTIMIZADAS PARA NOTIFICACIONES ==========

public class NotificationSubscription 
{ 
    public Guid Id { get; set; } = Guid.NewGuid(); 
    public Guid ApplicationId { get; set; } 
    public string EventType { get; set; } = string.Empty; // "Login", "Logout", "UserCreated", etc.
    public string? WebhookUrl { get; set; } // Opcional para WebSockets
    public string? SecretKey { get; set; } // Para validar la autenticidad del webhook con HMAC
    public string NotificationType { get; set; } = "webhook"; // "webhook", "websocket", "both"
    public string? WebSocketGroupName { get; set; } // Para agrupar conexiones WebSocket
    public bool? RequireAuthentication { get; set; } = true; // Si requiere autenticación para WebSocket
    public bool IsActive { get; set; } = true; 
    public DateTime CreatedAt { get; set; } = DateTime.Now; 
    public string? CreatedBy { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public string? ModifiedBy { get; set; }
}

public class NotificationLog 
{ 
    public long Id { get; set; } 
    public Guid SubscriptionId { get; set; } 
    public string EventType { get; set; } = string.Empty; 
    public Guid? UserId { get; set; } 
    public string? WebhookUrl { get; set; } = string.Empty; 
    public int? HttpStatusCode { get; set; } 
    public string? ResponseBody { get; set; } 
    public int? ResponseTime { get; set; } // en milisegundos
    public bool IsSuccess { get; set; } = false; 
    public string? ErrorMessage { get; set; } 
    public DateTime CreatedAt { get; set; } = DateTime.Now; 
}


// ========== NUEVAS ENTIDADES PARA WEBSOCKETS HÍBRIDOS ==========

public class WebSocketConnection
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ApplicationId { get; set; }
    public string ConnectionId { get; set; } = string.Empty;
    public Guid? UserId { get; set; } // NULL si es conexión anónima
    public string? BrowserId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime ConnectedAt { get; set; } = DateTime.Now;
    public DateTime? LastPingAt { get; set; }
    public DateTime? DisconnectedAt { get; set; }
    public bool IsActive { get; set; } = true;
}

public class WebSocketMessage 
{ 
    public long Id { get; set; } 
    public string ConnectionId { get; set; } = string.Empty; 
    public string EventType { get; set; } = string.Empty; 
    public string MessageData { get; set; } = string.Empty; 
    public DateTime SentAt { get; set; } = DateTime.Now; 
    public bool IsDelivered { get; set; } = false; 
    public DateTime? DeliveredAt { get; set; } 
    public string? ErrorMessage { get; set; } 
    public int RetryCount { get; set; } = 0; 
}

public class WebSocketStats
{
    public long Id { get; set; }
    public Guid ApplicationId { get; set; }
    public DateTime Date { get; set; }
    public int TotalConnections { get; set; } = 0;
    public int PeakConnections { get; set; } = 0;
    public int TotalMessages { get; set; } = 0;
    public int SuccessfulMessages { get; set; } = 0;
    public int FailedMessages { get; set; } = 0;
    public int? AverageConnectionDuration { get; set; } // en minutos
    public DateTime CreatedAt { get; set; } = DateTime.Now;
}

// ========== APROVISIONAMIENTO DE EMPLEADOS ==========

/// <summary>
/// Estado del aprovisionamiento de un empleado en AD Local → Entra ID → Office 365.
/// Los valores numéricos coinciden con HR.ref_Types.TypeId (Category = 'ProvisioningStatus')
/// para permitir JOINs desde reportes HR.
/// </summary>
public enum ProvisioningStatus
{
    Requested       = 2001,
    CreatedInLocalAd = 2002,
    PendingEntraSync = 2003,
    SyncedInEntra   = 2004,
    LicenseAssigned = 2005,
    LicenseFailed   = 2006,
    LocalAdFailed   = 2007
}

/// <summary>
/// Registro del ciclo de vida de aprovisionamiento de un empleado HR:
/// creación en AD Local → sincronización con Entra ID → asignación de licencia O365.
/// Las referencias a HR (HrEmployeeId, DepartmentId, EmployeeTypeId, ProvisioningStatusId)
/// son soft FKs cross-DB; los campos *Name guardan el valor desnormalizado para operar sin
/// consultar la BD HR.
/// </summary>
public class UserProvisioning
{
    public Guid Id { get; set; } = Guid.NewGuid();

    // ── Referencia HR ──────────────────────────────────────────────────────────
    public int HrEmployeeId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string? GivenName { get; set; }
    public string? Surname { get; set; }

    // ── Departamento (soft FK + desnormalizado) ────────────────────────────────
    public int? DepartmentId { get; set; }
    public string? DepartmentName { get; set; }

    public string? JobTitle { get; set; }

    // ── Tipo de empleado (soft FK a HR.ref_Types.TypeId, 1=Docente 2=Admin) ───
    public int EmployeeTypeId { get; set; }
    public string? EmployeeTypeName { get; set; }

    // ── Estado (soft FK a HR.ref_Types.TypeId, Category='ProvisioningStatus') ─
    public int ProvisioningStatusId { get; set; } = (int)ProvisioningStatus.Requested;
    public string? ProvisioningStatusName { get; set; } = nameof(ProvisioningStatus.Requested);

    // ── Resultado del aprovisionamiento ──────────────────────────────────────
    public Guid? AuthUserId { get; set; }
    public string? LocalAdObjectId { get; set; }
    public string? EntraObjectId { get; set; }
    public string? LicenseSkuId { get; set; }

    // ── Fechas ────────────────────────────────────────────────────────────────
    public DateTime? ProvisionedAt { get; set; }
    public DateTime? LicenseAssignedAt { get; set; }
    public DateTime? LastCheckedAt { get; set; }

    // ── Trazabilidad ─────────────────────────────────────────────────────────
    public string? ErrorMessage { get; set; }
    public string? RequestedBy { get; set; }

    /// <summary>Referencia al origen que disparó el aprovisionamiento (ej: "Contract:1234").</summary>
    public string? SourceReference { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public DateTime? UpdatedAt { get; set; }
}

// ========== PERFILES DE ACCESO (agrupan roles reutilizables) ==========

/// <summary>
/// Agrupa uno o varios Roles bajo un nombre reutilizable (ej. "Directora Administrativa" =
/// Jefe de Departamento + Empleado + Aprobador de Guardias). Asignar un perfil a un usuario
/// expande la asignación a filas concretas en UserRole (ver IAccessProfileAssignmentService);
/// el perfil NO participa en la resolución de menú ni de permisos — esos siempre se calculan
/// a partir de los roles efectivos del usuario.
/// </summary>
public class AccessProfile
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.Now;
    public bool IsDeleted { get; set; } = false;
}

/// <summary>Composición de un AccessProfile: qué roles agrupa.</summary>
public class AccessProfileRole
{
    public int AccessProfileId { get; set; }
    public int RoleId { get; set; }
}

/// <summary>
/// Registro de qué perfiles tiene asignado un usuario. Es informativo/de trazabilidad
/// (para mostrar "Perfil: Directora Administrativa" en UI y para poder revertir la
/// asignación de forma segura) — la autorización real siempre pasa por UserRole.
/// </summary>
public class UserAccessProfile
{
    public Guid UserId { get; set; }
    public int AccessProfileId { get; set; }
    public DateTime AssignedAt { get; set; } = DateTime.Now;
    public string? AssignedBy { get; set; }
    public bool IsDeleted { get; set; } = false;
}



