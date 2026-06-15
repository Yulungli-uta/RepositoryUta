namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>Credenciales para autenticar un usuario contra Active Directory local.</summary>
public record LocalAdAuthRequest(string Username, string Password);

/// <summary>Resultado de la autenticación contra AD local.</summary>
public record LocalAdAuthResponse(bool Success, string? Email, string? DisplayName, string? FailureReason = null);

/// <summary>Datos para crear un usuario en AD local.</summary>
public record CreateLocalAdUserRequest(
    string Email,
    string DisplayName,
    string? GivenName,
    string? Surname,
    string InitialPassword,
    bool ForcePasswordChange = true,
    string? JobTitle = null,
    string? Department = null,
    bool AccountEnabled = true,
    /// <summary>OU de destino. Si no se especifica, usa LocalAd:FuncionariosActivosOu de appsettings.</summary>
    string? TargetOu = null
);

/// <summary>Datos para actualizar un usuario en AD local (solo campos provistos).</summary>
public record UpdateLocalAdUserRequest(
    string? DisplayName,
    string? GivenName,
    string? Surname,
    string? JobTitle,
    string? Department
);

/// <summary>Usuario retornado por el directorio AD local.</summary>
public record LocalAdUserResponse(
    string Id,
    string Email,
    string DisplayName,
    string? GivenName,
    string? Surname,
    string? JobTitle,
    string? Department,
    bool AccountEnabled
);

/// <summary>Grupo retornado por el directorio AD local.</summary>
public record LocalAdGroupResponse(
    string Id,
    string Name,
    string? Description,
    string? Email
);

/// <summary>Datos para crear un grupo en AD local.</summary>
public record CreateLocalAdGroupRequest(
    string GroupName,
    string? Description = null
);

/// <summary>Cambio de contraseña de un usuario AD local por parte de un administrador.</summary>
public record ChangeLocalAdUserPasswordRequest(
    string NewPassword,
    bool ForcePasswordChange = true
);

/// <summary>Estado de sincronización de un usuario AD Local con Microsoft Entra ID.</summary>
public enum EntraSyncStatus
{
    /// <summary>No se ha verificado el estado.</summary>
    Unknown,
    /// <summary>Usuario creado en AD Local; aún no aparece en Microsoft Entra (pendiente de Entra Connect).</summary>
    PendingSync,
    /// <summary>Usuario existe en Microsoft Entra y está habilitado.</summary>
    Synced,
    /// <summary>Usuario existe en Microsoft Entra pero con accountEnabled = false.</summary>
    Disabled,
    /// <summary>Error al consultar Microsoft Graph.</summary>
    SyncError
}

/// <summary>Resultado de verificar la sincronización de un usuario en Microsoft Entra vía Graph.</summary>
public record EntraSyncResult(
    EntraSyncStatus Status,
    bool? AccountEnabled = null,
    string? AzureObjectId = null,
    string? Message = null
);

/// <summary>Usuario AD local con estado de sincronización Entra adjunto.</summary>
public record LocalAdUserWithSyncResponse(
    string Id,
    string Email,
    string DisplayName,
    string? GivenName,
    string? Surname,
    string? JobTitle,
    string? Department,
    bool AccountEnabled,
    EntraSyncResult? EntraSync = null
);
