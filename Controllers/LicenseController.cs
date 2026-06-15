using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Gestión de licencias Office 365 vía Microsoft Graph.
/// Endpoints de solo-lectura disponibles para usuarios autenticados;
/// escritura requiere rol Administrador.
/// </summary>
[ApiController, Route("api/licenses"), Authorize]
public class LicenseController : ControllerBase
{
    private readonly IMicrosoftLicenseService _svc;

    public LicenseController(IMicrosoftLicenseService svc) => _svc = svc;

    // ── SKUs del tenant ───────────────────────────────────────────────────────

    /// <summary>Lista todos los SKUs disponibles en el tenant con cupos.</summary>
    [HttpGet("skus")]
    public async Task<IActionResult> GetSkus(CancellationToken ct)
    {
        var skus = await _svc.GetSubscribedSkusAsync(ct);
        return Ok(ApiResponse.Ok(skus, $"{skus.Count} SKU(s) encontrados"));
    }

    // ── Licencias de un usuario ───────────────────────────────────────────────

    /// <summary>Retorna las licencias asignadas a un usuario por UPN.</summary>
    [HttpGet("users/{upn}")]
    public async Task<IActionResult> GetUserLicenses(string upn, CancellationToken ct)
    {
        var licenses = await _svc.GetUserLicensesAsync(upn, ct);
        return Ok(ApiResponse.Ok(licenses, $"{licenses.Count} licencia(s) asignadas a {upn}"));
    }

    // ── Asignación / remoción ─────────────────────────────────────────────────

    /// <summary>Asigna una licencia por SkuPartNumber a un usuario.</summary>
    [HttpPost("assign")]
    public async Task<IActionResult> Assign([FromBody] LicenseAssignRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Upn) || string.IsNullOrWhiteSpace(req.SkuPartNumber))
            return BadRequest(ApiResponse.Fail("Upn y SkuPartNumber son requeridos"));

        var result = await _svc.AssignLicenseAsync(req.Upn, req.SkuPartNumber, req.CountryCode, ct);
        return result.Success
            ? Ok(ApiResponse.Ok(result, result.Message))
            : UnprocessableEntity(ApiResponse.Fail(result.Message ?? "Error al asignar licencia"));
    }

    /// <summary>Asigna la licencia estándar de empleado (AppParam lic:employee).</summary>
    [HttpPost("assign-employee")]
    public async Task<IActionResult> AssignEmployee([FromBody] LicenseAssignEmployeeRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Upn))
            return BadRequest(ApiResponse.Fail("Upn es requerido"));

        var result = await _svc.AssignEmployeeLicenseAsync(req.Upn, req.CountryCode, ct);
        return result.Success
            ? Ok(ApiResponse.Ok(result, result.Message))
            : UnprocessableEntity(ApiResponse.Fail(result.Message ?? "Error al asignar licencia de empleado"));
    }

    /// <summary>Quita una licencia por SkuPartNumber de un usuario.</summary>
    [HttpPost("remove")]
    public async Task<IActionResult> Remove([FromBody] LicenseAssignRequest req, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Upn) || string.IsNullOrWhiteSpace(req.SkuPartNumber))
            return BadRequest(ApiResponse.Fail("Upn y SkuPartNumber son requeridos"));

        var result = await _svc.RemoveLicenseAsync(req.Upn, req.SkuPartNumber, ct);
        return result.Success
            ? Ok(ApiResponse.Ok(result, result.Message))
            : UnprocessableEntity(ApiResponse.Fail(result.Message ?? "Error al remover licencia"));
    }

    /// <summary>Configura el UsageLocation de un usuario (prerequisito para asignar licencias).</summary>
    [HttpPatch("users/{upn}/usage-location")]
    public async Task<IActionResult> SetUsageLocation(string upn, [FromQuery] string countryCode = "EC", CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(upn))
            return BadRequest(ApiResponse.Fail("Upn es requerido"));

        await _svc.SetUsageLocationAsync(upn, countryCode, ct);
        return Ok(ApiResponse.Ok(null, $"UsageLocation={countryCode} configurado para {upn}"));
    }
}
