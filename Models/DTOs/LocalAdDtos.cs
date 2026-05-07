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
    bool AccountEnabled = true
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
