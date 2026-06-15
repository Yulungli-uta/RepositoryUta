using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers.Academic;

/// <summary>
/// Operaciones AD Local para estudiantes (OU=ESTUDIANTES).
/// Solo ejecuta acciones en Active Directory. El estado se guarda en HrBackend.
/// </summary>
[ApiController]
[Route("api/academic/student-provisioning")]
public class StudentProvisioningController : ControllerBase
{
    private readonly IStudentProvisioningService _service;
    private readonly ILogger<StudentProvisioningController> _logger;

    public StudentProvisioningController(
        IStudentProvisioningService service,
        ILogger<StudentProvisioningController> logger)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _logger  = logger  ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Crea la cuenta AD en OU=Activos,OU=ESTUDIANTES y la añade a EActivos.
    /// Genera el email institucional y lo retorna. HrBackend persiste el estado.
    /// </summary>
    [HttpPost("students")]
    public async Task<IActionResult> CreateAdAccount(
        [FromBody] CreateStudentAdAccountRequest req,
        CancellationToken ct)
    {
        _logger.LogInformation(
            "POST student-provisioning/students. HrStudentId={Id}", req.HrStudentId);

        var result = await _service.CreateAdAccountAsync(req, ct);
        return result.Success
            ? Ok(new { data = result })
            : BadRequest(new { error = result.ErrorMessage, data = result });
    }

    /// <summary>
    /// Deshabilita la cuenta AD: desactiva, quita de EActivos, mueve a OU=Inactivos,OU=ESTUDIANTES.
    /// Recibe el AdObjectId (LocalAdObjectId almacenado en HrBackend).
    /// </summary>
    [HttpPost("ad-accounts/{adObjectId}/disable")]
    public async Task<IActionResult> DisableAdAccount(string adObjectId, CancellationToken ct)
    {
        _logger.LogInformation(
            "POST student-provisioning/ad-accounts/{Id}/disable", adObjectId);

        var result = await _service.DisableAdAccountAsync(adObjectId, ct);
        return result.Success
            ? Ok(new { data = result })
            : BadRequest(new { error = result.ErrorMessage, data = result });
    }
}
