using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Ciclo de vida de aprovisionamiento de empleados HR en AD Local → Entra ID → O365.
/// Todos los endpoints requieren autenticación. Las operaciones de escritura deben
/// restringirse al rol Administrador en producción.
/// </summary>
[ApiController, Route("api/provisioning"), Authorize(Roles = "Administrador,R_DITIC")]
public class ProvisioningController : ControllerBase
{
    private readonly IEmployeeProvisioningService _svc;
    private readonly ILogger<ProvisioningController> _logger;

    public ProvisioningController(IEmployeeProvisioningService svc, ILogger<ProvisioningController> logger)
    {
        _svc = svc;
        _logger = logger;
    }

    // ── Creación ──────────────────────────────────────────────────────────────

    /// <summary>Aprovisiona un único empleado en AD Local.</summary>
    [HttpPost("employees")]
    public async Task<IActionResult> Provision([FromBody] ProvisionEmployeeRequest req, CancellationToken ct)
    {

        var requestId = HttpContext.TraceIdentifier;
        var requestedBy = User?.Identity?.Name
                          ?? User?.FindFirst("email")?.Value
                          ?? User?.FindFirst("preferred_username")?.Value
                          ?? "unknown";

        _logger.LogInformation(
            "Iniciando aprovisionamiento de empleado. RequestId={RequestId}, RequestedBy={RequestedBy}, HrEmployeeId={HrEmployeeId}, DisplayName={DisplayName}, GivenName={GivenName}, Surname={Surname}, HasInitialPassword={HasInitialPassword}",
            requestId,
            requestedBy,
            req?.HrEmployeeId,
            req?.DisplayName,
            req?.GivenName,
            req?.Surname,
            !string.IsNullOrWhiteSpace(req?.InitialPassword)
        );

        if (req is null)
        {
            _logger.LogWarning(
                "Request nulo en aprovisionamiento. RequestId={RequestId}, RequestedBy={RequestedBy}",
                requestId,
                requestedBy
            );

            return BadRequest(ApiResponse.Fail("El cuerpo de la solicitud es requerido"));
        }

        // Email es generado internamente — excluir de la validación automática de ModelState
        ModelState.Remove("Email");
        if (!ModelState.IsValid)
            return ValidationProblem(ModelState);

        if (string.IsNullOrWhiteSpace(req.DisplayName)
            || string.IsNullOrWhiteSpace(req.GivenName) || string.IsNullOrWhiteSpace(req.Surname))
            return BadRequest(ApiResponse.Fail("DisplayName, GivenName y Surname son requeridos"));

        if (string.IsNullOrWhiteSpace(req.InitialPassword))
            return BadRequest(ApiResponse.Fail("InitialPassword es requerida para crear el usuario en AD"));

        if (req.HrEmployeeId <= 0)
            return BadRequest(ApiResponse.Fail("HrEmployeeId debe ser un valor positivo"));

        SetRequestedBy(req);
        try
        {
            _logger.LogInformation(
                "Enviando solicitud al servicio de aprovisionamiento. RequestId={RequestId}, RequestedBy={RequestedBy}, HrEmployeeId={HrEmployeeId}",
                requestId,
                requestedBy,
                req.HrEmployeeId
            );  
            var result = await _svc.ProvisionAsync(req, ct);
            return CreatedAtAction(nameof(GetStatus), new { id = result.Id },
                ApiResponse.Ok(result, "Aprovisionamiento iniciado. Verifique el estado de sincronización con Entra."));
        }
        catch (DuplicateProvisioningException ex)
        {
            _logger.LogInformation("Intento de aprovisionamiento duplicado: {Message}", ex.Message);
            return Conflict(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>Aprovisiona múltiples empleados en paralelo (máx. 5 concurrentes).</summary>
    [HttpPost("employees/bulk")]
    public async Task<IActionResult> ProvisionBulk([FromBody] List<ProvisionEmployeeRequest> requests, CancellationToken ct)
    {
        if (requests is not { Count: > 0 })
            return BadRequest(ApiResponse.Fail("Se requiere al menos un empleado en el lote"));

        if (requests.Count > 200)
            return BadRequest(ApiResponse.Fail("El lote no puede superar 200 empleados por solicitud"));

        foreach (var r in requests)
            SetRequestedBy(r);

        var results = await _svc.ProvisionBulkAsync(requests, ct);
        var ok = results.Count(r => r.Success);
        var failed = results.Count(r => !r.Success);
        return Ok(ApiResponse.Ok(results, $"Lote procesado: {ok} exitosos, {failed} fallidos de {results.Count} total"));
    }

    // ── Consulta ──────────────────────────────────────────────────────────────

    /// <summary>Retorna el estado de un aprovisionamiento por Id.</summary>
    [HttpGet("employees/{id:guid}")]
    public async Task<IActionResult> GetStatus(Guid id, CancellationToken ct)
    {
        var result = await _svc.GetStatusAsync(id, ct);
        return result is null
            ? NotFound(ApiResponse.Fail($"Aprovisionamiento '{id}' no encontrado"))
            : Ok(ApiResponse.Ok(result));
    }

    /// <summary>Lista aprovisionamientos con paginación y filtro opcional por estado.</summary>
    [HttpGet("employees")]
    public async Task<IActionResult> List(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] int? statusId = null,
        CancellationToken ct = default)
    {
        if (page < 1) page = 1;
        if (pageSize is < 1 or > 200) pageSize = 50;

        var result = await _svc.ListAsync(page, pageSize, statusId, ct);
        return Ok(ApiResponse.Ok(result));
    }

    // ── Acciones ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Reintenta un aprovisionamiento fallido.
    /// LocalAdFailed: requiere InitialPassword en el body para recriar la cuenta en AD.
    /// LicenseFailed: delega al flujo de completado (Entra sync → licencia), no requiere contraseña.
    /// </summary>
    [HttpPatch("employees/{id:guid}/retry")]
    public async Task<IActionResult> Retry(Guid id, [FromBody] RetryProvisioningRequest? req, CancellationToken ct)
    {
        try
        {
            var result = await _svc.RetryAsync(id, req?.InitialPassword, ct);
            return result is null
                ? NotFound(ApiResponse.Fail($"Aprovisionamiento '{id}' no encontrado"))
                : Ok(ApiResponse.Ok(result, "Reintento ejecutado"));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    // ── Completado (Entra sync → licencia) ───────────────────────────────────

    /// <summary>
    /// Verifica si el usuario ya sincronizó con Entra y, si es así, asigna la licencia O365.
    /// Transiciones: PendingEntraSync → SyncedInEntra → LicenseAssigned / LicenseFailed.
    /// </summary>
    [HttpPost("employees/{id:guid}/complete")]
    public async Task<IActionResult> Complete(Guid id, CancellationToken ct)
    {
        var result = await _svc.CheckAndCompleteProvisioningAsync(id, ct);
        return result is null
            ? NotFound(ApiResponse.Fail($"Aprovisionamiento '{id}' no encontrado"))
            : Ok(ApiResponse.Ok(result, $"Estado actualizado: {result.ProvisioningStatusName}"));
    }

    /// <summary>
    /// Procesa todos los registros en estado PendingEntraSync, SyncedInEntra o LicenseFailed.
    /// Útil para ejecutar desde el dashboard de administración o una tarea programada.
    /// </summary>
    [HttpPost("employees/complete-pending")]
    public async Task<IActionResult> CompletePending(CancellationToken ct)
    {
        var result = await _svc.CompletePendingAsync(ct);
        return Ok(ApiResponse.Ok(result,
            $"Procesados: {result.TotalProcessed} — " +
            $"Licencias asignadas: {result.LicenseAssigned} — " +
            $"Aún pendientes: {result.StillPending} — " +
            $"Fallidos: {result.Failed}"));
    }

    // ── Restablecimiento de contraseña ────────────────────────────────────────

    /// <summary>
    /// Restablece la contraseña en AD Local para un empleado aprovisionado.
    /// Genera una contraseña temporal con ForcePasswordChange=true.
    /// Solo aplica a registros con cuenta AD Local (estado &gt;= CreatedInLocalAd).
    /// </summary>
    [HttpPost("employees/{id:guid}/reset-password")]
    public async Task<IActionResult> ResetPassword(Guid id, CancellationToken ct)
    {
        try
        {
            var result = await _svc.ResetPasswordAsync(id, ct);
            return result is null
                ? NotFound(ApiResponse.Fail($"Aprovisionamiento '{id}' no encontrado"))
                : Ok(ApiResponse.Ok(result, "Contraseña restablecida. Entregue las credenciales al empleado de forma segura."));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    // ── Deshabilitar cuenta ───────────────────────────────────────────────────

    /// <summary>
    /// Deshabilita la cuenta institucional de un empleado por HrEmployeeId (int).
    /// Se invoca desde HrBackend cuando una acción de personal tiene RequiresAdUserDisable = true.
    /// Desactiva en AD Local, mueve a OU Inactivos, quita del grupo activo y
    /// pone auth.tbl_Users.IsActive = false.
    /// </summary>
    [HttpPost("employees/{hrEmployeeId:int}/disable")]
    public async Task<IActionResult> DisableEmployee(int hrEmployeeId, CancellationToken ct)
    {
        var result = await _svc.DisableEmployeeAsync(hrEmployeeId, ct);
        return result.Success
            ? Ok(ApiResponse.Ok(result, "Cuenta institucional deshabilitada."))
            : BadRequest(ApiResponse.Fail(result.ErrorMessage ?? "Error al deshabilitar la cuenta."));
    }

    /// <summary>
    /// Deshabilita por ID de registro de aprovisionamiento (Guid).
    /// Usado desde el dashboard de aprovisionamiento donde se conoce el ProvisioningId.
    /// </summary>
    [HttpPost("employees/{id:guid}/disable")]
    public async Task<IActionResult> DisableByProvisioningId(Guid id, CancellationToken ct)
    {
        var result = await _svc.DisableByProvisioningIdAsync(id, ct);
        if (result is null)
            return NotFound(ApiResponse.Fail($"Aprovisionamiento '{id}' no encontrado."));
        return result.Success
            ? Ok(ApiResponse.Ok(result, "Cuenta institucional deshabilitada."))
            : BadRequest(ApiResponse.Fail(result.ErrorMessage ?? "Error al deshabilitar la cuenta."));
    }

    /// <summary>
    /// Deshabilita por GUID del objeto AD Local (para llamadas desde gestión AD Local
    /// donde se conoce el objectGUID de LDAP pero no el ID de aprovisionamiento).
    /// </summary>
    [HttpPost("employees/by-ad-id/{adObjectId}/disable")]
    public async Task<IActionResult> DisableByAdObjectId(string adObjectId, CancellationToken ct)
    {
        var result = await _svc.DisableByAdIdAsync(adObjectId, ct);
        if (result is null)
            return NotFound(ApiResponse.Fail($"Sin registro de aprovisionamiento para el objeto AD '{adObjectId}'."));
        return result.Success
            ? Ok(ApiResponse.Ok(result, "Cuenta institucional deshabilitada."))
            : BadRequest(ApiResponse.Fail(result.ErrorMessage ?? "Error al deshabilitar la cuenta."));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>Inyecta el email del usuario autenticado como RequestedBy (sin modificar el record).</summary>
    private void SetRequestedBy(ProvisionEmployeeRequest req)
    {
        // No modifica el record del request (es immutable); el servicio debe recibirlo desde el contexto.
        // Esta firma está disponible para auditoría vía el caller si se requiere.
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value
                 ?? User.FindFirst("email")?.Value;
        if (!string.IsNullOrWhiteSpace(email))
            _logger.LogInformation("Aprovisionamiento solicitado por {RequestedBy} para empleado {EmployeeId}",
                email, req.HrEmployeeId);
    }
}
