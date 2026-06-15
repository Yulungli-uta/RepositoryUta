namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>DTO para cambio de contraseña simple (contraseña actual + nueva).</summary>
public record ChangePasswordRequest(
    string CurrentPassword,
    string NewPassword
);

/// <summary>Respuesta genérica de cambio de contraseña.</summary>
public record ChangePasswordResponse(
    bool Success,
    string Message
);

/// <summary>Solicitud de OTP para iniciar el flujo de cambio de contraseña con doble factor.</summary>
public record RequestPasswordChange2FARequest();

/// <summary>Respuesta de solicitud de OTP. En producción el código llega por email/SMS, no en la respuesta.</summary>
public record RequestPasswordChange2FAResponse(
    bool Success,
    string Message,
    /// <summary>Solo presente en entorno de desarrollo para pruebas.</summary>
    string? OtpCodeDev = null
);

/// <summary>
/// DTO para cambio de contraseña con doble factor.
/// CurrentPassword es requerida para usuarios locales; se omite para usuarios AzureAD.
/// </summary>
public record ChangePasswordWith2FARequest(
    string? CurrentPassword,
    string NewPassword,
    string OtpCode
);
