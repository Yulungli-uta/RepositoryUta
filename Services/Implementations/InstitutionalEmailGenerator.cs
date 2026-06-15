using System.Globalization;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public sealed class InstitutionalEmailGenerator : IInstitutionalEmailGenerator
{
    private const int MaxAttempts = 100;

    private readonly AuthDbContext _context;
    private readonly IIdentityProviderResolver _resolver;
    private readonly IOptions<LocalAdOptions> _adOptions;
    private readonly ILogger<InstitutionalEmailGenerator> _logger;

    public InstitutionalEmailGenerator(
        AuthDbContext context,
        IIdentityProviderResolver resolver,
        IOptions<LocalAdOptions> adOptions,
        ILogger<InstitutionalEmailGenerator> logger)
    {
        _context   = context;
        _resolver  = resolver;
        _adOptions = adOptions;
        _logger    = logger;
    }

    public async Task<string> GenerateAvailableEmailAsync(
        int hrEmployeeId,
        string givenName,
        string surname,
        CancellationToken ct = default)
    {
        var alias  = BuildBaseAlias(givenName, surname);
        var domain = GetExpectedDomain();
        var baseEmail = $"{alias}@{domain}";

        _logger.LogInformation(
            "[EMAIL-GEN] ══ INICIO GENERACIÓN ══ HrEmployeeId={HrEmployeeId} | " +
            "GivenName='{GivenName}' | Surname='{Surname}' | " +
            "AliasBase='{Alias}' | Dominio='{Domain}' | CandidatoBase='{BaseEmail}'",
            hrEmployeeId, givenName, surname, alias, domain, baseEmail);

        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var candidateAlias = attempt == 0 ? alias : $"{alias}{attempt}";
            var email          = $"{candidateAlias}@{domain}";

            var (available, motivo) = await CheckAvailabilityAsync(email, hrEmployeeId, ct);

            if (!available)
            {
                _logger.LogError(
                    "[EMAIL-GEN] ✗ CONFLICTO en intento {Attempt}: '{Email}' YA EXISTE — Motivo={Motivo} | " +
                    "HrEmployeeId={HrEmployeeId} | Próximo candidato='{Next}'",
                    attempt, email, motivo, hrEmployeeId,
                    attempt + 1 < MaxAttempts ? $"{alias}{attempt + 1}@{domain}" : "(agotado)");
                continue;
            }

            _logger.LogInformation(
                "[EMAIL-GEN] ✓ Email disponible encontrado en intento {Attempt}: '{Email}' | HrEmployeeId={HrEmployeeId}",
                attempt, email, hrEmployeeId);

            _logger.LogInformation(
                "[EMAIL-GEN] ══ RESULTADO FINAL ══\n" +
                "  HrEmployeeId      : {HrEmployeeId}\n" +
                "  Nombre completo   : {GivenName} {Surname}\n" +
                "  Email generado    : {Email}\n" +
                "  Alias base        : {Alias}\n" +
                "  Sufijo numérico   : {Suffix}\n" +
                "  Intentos usados   : {Attempt}",
                hrEmployeeId, givenName, surname, email, alias,
                attempt == 0 ? "(ninguno)" : attempt.ToString(),
                attempt + 1);

            return email;
        }

        _logger.LogError(
            "[EMAIL-GEN] ✗ AGOTADOS {MaxAttempts} intentos para HrEmployeeId={HrEmployeeId} | AliasBase='{Alias}@{Domain}'",
            MaxAttempts, hrEmployeeId, alias, domain);

        throw new InvalidOperationException(
            $"No se pudo generar un correo institucional disponible para el empleado {hrEmployeeId}.");
    }

    /// <summary>
    /// Verifica disponibilidad en tbl_UserProvisionings, tbl_Users y AD Local.
    /// Retorna (true, null) si disponible; (false, motivo) si ya existe.
    /// </summary>
    private async Task<(bool Available, string? Motivo)> CheckAvailabilityAsync(
        string email, int hrEmployeeId, CancellationToken ct)
    {
        // 1. ¿Existe en aprovisionamientos de OTRO empleado (activos)?
        var provisioningConflict = await _context.UserProvisionings
            .Where(p => p.Email == email &&
                        p.HrEmployeeId != hrEmployeeId &&
                        p.ProvisioningStatusId != (int)ProvisioningStatus.LocalAdFailed)
            .Select(p => new { p.HrEmployeeId, p.ProvisioningStatusName })
            .FirstOrDefaultAsync(ct);

        if (provisioningConflict is not null)
        {
            _logger.LogError(
                "[EMAIL-GEN] Conflicto tbl_UserProvisionings: '{Email}' asignado a HrEmployeeId={OtroEmpleado} " +
                "en estado '{Status}'",
                email, provisioningConflict.HrEmployeeId, provisioningConflict.ProvisioningStatusName);
            return (false, $"tbl_UserProvisionings (empleado={provisioningConflict.HrEmployeeId}, estado={provisioningConflict.ProvisioningStatusName})");
        }

        // 2. ¿Existe en tbl_Users?
        var hasUser = await _context.Users.AnyAsync(u => u.Email == email, ct);
        if (hasUser)
        {
            _logger.LogError(
                "[EMAIL-GEN] Conflicto tbl_Users: '{Email}' ya tiene registro en auth", email);
            return (false, "tbl_Users (cuenta auth ya existe)");
        }

        // 3. ¿Existe en AD Local?
        var dir    = _resolver.GetDirectory("LocalAd");
        var adUser = await dir.GetUserByEmailAsync(email, ct);
        if (adUser is not null)
        {
            _logger.LogError(
                "[EMAIL-GEN] Conflicto AD Local: '{Email}' ya existe en Active Directory (ObjectId={ObjectId})",
                email, adUser.Id);
            return (false, $"AD Local (ObjectId={adUser.Id})");
        }

        return (true, null);
    }

    private string GetExpectedDomain()
    {
        var fromBaseDn = string.Join(".", _adOptions.Value.BaseDn
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(p => p[3..]));

        return string.IsNullOrWhiteSpace(fromBaseDn)
            ? "uta.edu.ec"
            : fromBaseDn.ToLowerInvariant();
    }

    private static string BuildBaseAlias(string givenName, string surname)
    {
        var names = Tokenize(givenName);
        var surnames = Tokenize(surname);

        if (names.Count == 0)
            throw new InvalidOperationException("No se puede generar correo institucional sin nombres.");

        if (surnames.Count == 0)
            throw new InvalidOperationException("No se puede generar correo institucional sin apellidos.");

        var initials = new StringBuilder();
        initials.Append(names[0][0]);

        if (names.Count > 1)
            initials.Append(names[1][0]);

        return $"{initials}.{surnames[0]}";
    }

    private static List<string> Tokenize(string value)
        => Normalize(value)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(KeepAllowedAliasChars)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToList();

    private static string Normalize(string value)
    {
        var normalized = value.Trim().ToLowerInvariant().Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(normalized.Length);

        foreach (var c in normalized)
        {
            var category = CharUnicodeInfo.GetUnicodeCategory(c);
            if (category != UnicodeCategory.NonSpacingMark)
                builder.Append(c == 'ñ' ? 'n' : c);
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }

    private static string KeepAllowedAliasChars(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (c is >= 'a' and <= 'z' or >= '0' and <= '9')
                builder.Append(c);
        }

        return builder.ToString();
    }
}
