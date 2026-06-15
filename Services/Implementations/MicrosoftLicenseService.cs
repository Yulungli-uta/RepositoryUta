using Microsoft.EntityFrameworkCore;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using Microsoft.Graph.Users.Item.AssignLicense;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public class MicrosoftLicenseService : IMicrosoftLicenseService
{
    private readonly GraphServiceClient _graph;
    private readonly AuthDbContext _context;
    private readonly ILogger<MicrosoftLicenseService> _logger;

    public MicrosoftLicenseService(
        GraphServiceClient graph,
        AuthDbContext context,
        ILogger<MicrosoftLicenseService> logger)
    {
        _graph = graph;
        _context = context;
        _logger = logger;
    }

    // ── SKUs del tenant ───────────────────────────────────────────────────────

    public async Task<IReadOnlyList<SubscribedSkuDto>> GetSubscribedSkusAsync(CancellationToken ct = default)
    {
        try
        {
            var resp = await _graph.SubscribedSkus.GetAsync(cancellationToken: ct);
            var skus = resp?.Value ?? [];

            return skus.Select(s => new SubscribedSkuDto(
                SkuId: s.SkuId ?? Guid.Empty,
                SkuPartNumber: s.SkuPartNumber ?? string.Empty,
                CapabilityStatus: s.CapabilityStatus,
                PrepaidUnitsEnabled: s.PrepaidUnits?.Enabled,
                ConsumedUnits: s.ConsumedUnits,
                AvailableUnits: (s.PrepaidUnits?.Enabled ?? 0) - (s.ConsumedUnits ?? 0)
            )).ToList();
        }
        catch (ODataError ex)
        {
            _logger.LogError(ex, "Graph error al consultar subscribedSkus: {Code}", ex.Error?.Code);
            throw new InvalidOperationException($"Error al consultar SKUs del tenant: {ex.Error?.Message}", ex);
        }
    }

    // ── Licencias del usuario ────────────────────────────────────────────────

    public async Task<IReadOnlyList<UserLicenseDto>> GetUserLicensesAsync(string upn, CancellationToken ct = default)
    {
        try
        {
            var resp = await _graph.Users[upn].LicenseDetails.GetAsync(cancellationToken: ct);
            var details = resp?.Value ?? [];

            return details.Select(d => new UserLicenseDto(
                SkuId: d.SkuId ?? Guid.Empty,
                SkuPartNumber: d.SkuPartNumber
            )).ToList();
        }
        catch (ODataError ex) when (ex.ResponseStatusCode == 404)
        {
            _logger.LogWarning("Usuario {Upn} no encontrado en Entra al consultar licencias", upn);
            return [];
        }
        catch (ODataError ex)
        {
            _logger.LogError(ex, "Graph error al consultar licencias de {Upn}: {Code}", upn, ex.Error?.Code);
            throw new InvalidOperationException($"Error al consultar licencias del usuario: {ex.Error?.Message}", ex);
        }
    }

    // ── Asignar licencia ──────────────────────────────────────────────────────

    public async Task<LicenseOperationResult> AssignLicenseAsync(
        string upn, string skuPartNumber, string countryCode = "EC", CancellationToken ct = default)
    {
        try
        {
            var skuId = await GetSkuIdByPartNumberAsync(skuPartNumber, ct);
            if (skuId is null)
                return new LicenseOperationResult(false, upn, skuPartNumber, null,
                    $"SKU '{skuPartNumber}' no encontrado en los SKUs del tenant");

            // Verificar cupos disponibles
            var skus = await GetSubscribedSkusAsync(ct);
            var sku = skus.FirstOrDefault(s => s.SkuId == skuId.Value);
            if (sku is { AvailableUnits: <= 0 })
                return new LicenseOperationResult(false, upn, skuPartNumber, skuId,
                    $"Sin licencias disponibles para '{skuPartNumber}' (disponibles: {sku.AvailableUnits})");

            // Prerequisito: UsageLocation debe estar configurado
            if (!string.IsNullOrWhiteSpace(countryCode))
                await SetUsageLocationAsync(upn, countryCode, ct);

            var body = new AssignLicensePostRequestBody
            {
                AddLicenses = [new AssignedLicense { SkuId = skuId }],
                RemoveLicenses = []
            };

            await _graph.Users[upn].AssignLicense.PostAsync(body, cancellationToken: ct);
            _logger.LogInformation("Licencia {Sku} asignada a {Upn}", skuPartNumber, upn);

            return new LicenseOperationResult(true, upn, skuPartNumber, skuId,
                $"Licencia '{skuPartNumber}' asignada exitosamente");
        }
        catch (ODataError ex) when (ex.ResponseStatusCode == 404)
        {
            var msg = $"Usuario '{upn}' no encontrado en Entra. ¿Ya sincronizó con Entra Connect?";
            _logger.LogWarning("{Message}", msg);
            return new LicenseOperationResult(false, upn, skuPartNumber, null, msg);
        }
        catch (ODataError ex)
        {
            var msg = ex.Error?.Message ?? ex.Message;
            _logger.LogError(ex, "Graph error al asignar licencia {Sku} a {Upn}: {Code}", skuPartNumber, upn, ex.Error?.Code);
            return new LicenseOperationResult(false, upn, skuPartNumber, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al asignar licencia {Sku} a {Upn}", skuPartNumber, upn);
            return new LicenseOperationResult(false, upn, skuPartNumber, null, ex.Message);
        }
    }

    // ── Quitar licencia ───────────────────────────────────────────────────────

    public async Task<LicenseOperationResult> RemoveLicenseAsync(
        string upn, string skuPartNumber, CancellationToken ct = default)
    {
        try
        {
            var skuId = await GetSkuIdByPartNumberAsync(skuPartNumber, ct);
            if (skuId is null)
                return new LicenseOperationResult(false, upn, skuPartNumber, null,
                    $"SKU '{skuPartNumber}' no encontrado en los SKUs del tenant");

            var body = new AssignLicensePostRequestBody
            {
                AddLicenses = [],
                RemoveLicenses = [skuId]
            };

            await _graph.Users[upn].AssignLicense.PostAsync(body, cancellationToken: ct);
            _logger.LogInformation("Licencia {Sku} removida de {Upn}", skuPartNumber, upn);

            return new LicenseOperationResult(true, upn, skuPartNumber, skuId,
                $"Licencia '{skuPartNumber}' removida exitosamente");
        }
        catch (ODataError ex) when (ex.ResponseStatusCode == 404)
        {
            return new LicenseOperationResult(false, upn, skuPartNumber, null,
                $"Usuario '{upn}' no encontrado en Entra");
        }
        catch (ODataError ex)
        {
            var msg = ex.Error?.Message ?? ex.Message;
            _logger.LogError(ex, "Graph error al remover licencia {Sku} de {Upn}: {Code}", skuPartNumber, upn, ex.Error?.Code);
            return new LicenseOperationResult(false, upn, skuPartNumber, null, msg);
        }
    }

    // ── Asignar licencia de empleado (SKU único para todos los empleados) ────────

    public async Task<LicenseOperationResult> AssignEmployeeLicenseAsync(
        string upn, string countryCode = "EC", CancellationToken ct = default)
    {
        const string nemonic = "lic:employee";
        var param = await _context.AppParams.FindAsync([nemonic], ct);

        if (param is null || string.IsNullOrWhiteSpace(param.Value))
        {
            var msg = $"No hay SKU de empleado configurado. Configure AppParam '{nemonic}' con el SkuPartNumber del tenant.";
            _logger.LogWarning("{Message}", msg);
            return new LicenseOperationResult(false, upn, null, null, msg);
        }

        return await AssignLicenseAsync(upn, param.Value, countryCode, ct);
    }

    // ── UsageLocation ─────────────────────────────────────────────────────────

    public async Task SetUsageLocationAsync(string upn, string countryCode, CancellationToken ct = default)
    {
        try
        {
            await _graph.Users[upn].PatchAsync(
                new Microsoft.Graph.Models.User { UsageLocation = countryCode.ToUpperInvariant() },
                cancellationToken: ct);

            _logger.LogInformation("UsageLocation={Country} configurado para {Upn}", countryCode, upn);
        }
        catch (ODataError ex) when (ex.ResponseStatusCode == 404)
        {
            throw new InvalidOperationException(
                $"Usuario '{upn}' no encontrado en Entra al configurar UsageLocation", ex);
        }
        catch (ODataError ex)
        {
            _logger.LogError(ex, "Graph error al configurar UsageLocation para {Upn}: {Code}", upn, ex.Error?.Code);
            throw new InvalidOperationException($"Error al configurar UsageLocation: {ex.Error?.Message}", ex);
        }
    }

    // ── Resolver SkuId desde SkuPartNumber ────────────────────────────────────

    public async Task<Guid?> GetSkuIdByPartNumberAsync(string skuPartNumber, CancellationToken ct = default)
    {
        var skus = await GetSubscribedSkusAsync(ct);
        var match = skus.FirstOrDefault(s =>
            string.Equals(s.SkuPartNumber, skuPartNumber, StringComparison.OrdinalIgnoreCase));
        return match?.SkuId == Guid.Empty ? null : match?.SkuId;
    }
}
