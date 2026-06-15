namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>
/// Solicitud para crear una cuenta AD de estudiante en OU=Activos,OU=ESTUDIANTES.
/// El estado y seguimiento del aprovisionamiento se almacena en HrBackend (tbl_StudentProvisioning).
/// RepositoryUta solo realiza la operación AD y retorna el AdObjectId generado.
/// </summary>
public record CreateStudentAdAccountRequest(
    /// <summary>StudentId de HrBackend (solo para logging/trazabilidad).</summary>
    int HrStudentId,

    string DisplayName,
    string GivenName,
    string Surname,

    /// <summary>Contraseña inicial; debe cumplir la política de complejidad de AD.</summary>
    string InitialPassword,

    /// <summary>Cédula del estudiante. Persiste como employeeID en AD Local.</summary>
    string? IdCard = null,

    /// <summary>Referencia al período académico, ej: "Enrollment:2024-I".</summary>
    string? SourceReference = null,

    bool ForcePasswordChange = true
);

/// <summary>Resultado de la creación de cuenta AD para un estudiante.</summary>
public record CreateStudentAdAccountResult(
    bool Success,
    /// <summary>DN o GUID en AD Local. HrBackend lo persiste en su tbl_StudentProvisioning.</summary>
    string? AdObjectId,
    /// <summary>Email institucional generado por RepositoryUta (ej: jsmith@uta.edu.ec).</summary>
    string? Email,
    string? ErrorMessage
);

/// <summary>Resultado de deshabilitar la cuenta AD de un estudiante.</summary>
public record DisableStudentAdAccountResult(
    bool Success,
    string AdObjectId,
    string? ErrorMessage
);
