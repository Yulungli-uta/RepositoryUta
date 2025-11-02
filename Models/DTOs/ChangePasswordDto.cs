namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>
/// DTO para cambio de contraseña de usuario
/// </summary>
public record ChangePasswordRequest(
    string CurrentPassword, 
    string NewPassword
);

/// <summary>
/// Respuesta del cambio de contraseña
/// </summary>
public record ChangePasswordResponse(
    bool Success, 
    string Message
);
