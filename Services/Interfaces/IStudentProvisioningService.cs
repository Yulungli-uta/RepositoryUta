using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

/// <summary>
/// Operaciones AD para estudiantes (OU=ESTUDIANTES).
/// Solo interactúa con Active Directory Local — sin persistencia en RepositoryUta.
/// El seguimiento de estado se almacena en HrBackend (tbl_StudentProvisioning).
/// </summary>
public interface IStudentProvisioningService
{
    /// <summary>
    /// Crea la cuenta AD en OU=Activos,OU=ESTUDIANTES y la añade al grupo EActivos.
    /// Genera el email institucional internamente y lo retorna en el resultado.
    /// </summary>
    Task<CreateStudentAdAccountResult> CreateAdAccountAsync(
        CreateStudentAdAccountRequest req,
        CancellationToken ct = default);

    /// <summary>
    /// Deshabilita la cuenta AD: desactiva, quita de EActivos y mueve a OU=Inactivos,OU=ESTUDIANTES.
    /// </summary>
    Task<DisableStudentAdAccountResult> DisableAdAccountAsync(
        string adObjectId,
        CancellationToken ct = default);
}
