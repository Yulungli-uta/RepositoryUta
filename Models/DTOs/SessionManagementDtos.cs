namespace WsSeguUta.AuthSystem.API.Models.DTOs;

// ─── Sesiones de usuario ──────────────────────────────────────────────────────

/// <summary>DTO de una sesión activa de usuario para el panel de administración.</summary>
public sealed class ActiveSessionDto
{
    public Guid SessionId { get; init; }
    public Guid UserId { get; init; }
    public string Email { get; init; } = string.Empty;
    public string? DisplayName { get; init; }
    public string UserType { get; init; } = string.Empty;
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? BrowserId { get; init; }
    public DateTime LoginAt { get; init; }
    public DateTime? LastActivityAt { get; init; }
    public DateTime ExpiresAt { get; init; }
    public string Status { get; init; } = string.Empty;
    public bool IsWebSocketConnected { get; init; }
    public DateTime? WsLastPing { get; init; }
}

/// <summary>Respuesta tras revocar una sesión.</summary>
public sealed class RevokeSessionResultDto
{
    public Guid SessionId { get; init; }
    public bool WasNotified { get; init; }
    public string Message { get; init; } = string.Empty;
}

// ─── Clientes API ─────────────────────────────────────────────────────────────

/// <summary>DTO de un cliente API para el panel de administración.</summary>
public sealed class ActiveApiClientDto
{
    public Guid Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string ClientId { get; init; } = string.Empty;
    public string? Description { get; init; }
    public bool IsActive { get; init; }
    public DateTime CreatedAt { get; init; }
    public string? CreatedBy { get; init; }
    public DateTime? LastUsedAt { get; init; }
    public DateTime? SecretRotatedAt { get; init; }
    public string? SecretRotatedBy { get; init; }
    public DateTime? SuspendedAt { get; init; }
    public string? SuspendedBy { get; init; }
    public int CallsLast24h { get; init; }
    public string? LastIpAddress { get; init; }
    public string? LastUserAgent { get; init; }
}

/// <summary>Respuesta tras rotar el secret de un cliente API.</summary>
public sealed class RotateSecretResultDto
{
    public Guid ApplicationId { get; init; }
    public string ClientId { get; init; } = string.Empty;
    /// <summary>Nuevo secret en texto plano — mostrar solo una vez.</summary>
    public string NewClientSecret { get; init; } = string.Empty;
    public DateTime RotatedAt { get; init; }
}

/// <summary>Respuesta tras activar/suspender un cliente API.</summary>
public sealed class ToggleClientResultDto
{
    public Guid ApplicationId { get; init; }
    public string ClientId { get; init; } = string.Empty;
    public bool IsActive { get; init; }
    public string Message { get; init; } = string.Empty;
}
