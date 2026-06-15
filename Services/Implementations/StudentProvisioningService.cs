using Microsoft.Extensions.Options;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

/// <summary>
/// Realiza operaciones AD Local para estudiantes (OU=ESTUDIANTES).
/// No persiste en RepositoryUta — el estado vive en HrBackend.tbl_StudentProvisioning.
/// </summary>
public class StudentProvisioningService : IStudentProvisioningService
{
    private readonly IIdentityProviderResolver _resolver;
    private readonly IOptions<LocalAdOptions> _adOpts;
    private readonly IOptions<ProvisioningOptions> _provOpts;
    private readonly IInstitutionalEmailGenerator _emailGenerator;
    private readonly ILogger<StudentProvisioningService> _logger;

    public StudentProvisioningService(
        IIdentityProviderResolver resolver,
        IOptions<LocalAdOptions> adOpts,
        IOptions<ProvisioningOptions> provOpts,
        IInstitutionalEmailGenerator emailGenerator,
        ILogger<StudentProvisioningService> logger)
    {
        _resolver       = resolver;
        _adOpts         = adOpts;
        _provOpts       = provOpts;
        _emailGenerator = emailGenerator;
        _logger         = logger;
    }

    // ── Crear cuenta ──────────────────────────────────────────────────────────

    public async Task<CreateStudentAdAccountResult> CreateAdAccountAsync(
        CreateStudentAdAccountRequest req,
        CancellationToken ct = default)
    {
        _logger.LogInformation(
            "[STUDENT-AD] Creando cuenta AD. HrStudentId={Id} | Nombre={Name}",
            req.HrStudentId, req.DisplayName);

        string email;
        try
        {
            email = await _emailGenerator.GenerateAvailableEmailAsync(
                req.HrStudentId, req.GivenName, req.Surname, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[STUDENT-AD] Error al generar email para HrStudentId={Id}", req.HrStudentId);
            return new CreateStudentAdAccountResult(false, null, null, ex.Message);
        }

        try
        {
            var dir = _resolver.GetDirectory("LocalAd");

            var dirUser = new DirectoryUser(
                string.Empty,
                email,
                req.DisplayName,
                req.GivenName,
                req.Surname,
                null, null,
                AccountEnabled: true,
                CreatedDateTime: null,
                IdCard: req.IdCard);

            var created = await dir.CreateUserAsync(
                dirUser, req.InitialPassword, _adOpts.Value.EstudiantesActivosOu, req.ForcePasswordChange, ct);

            _logger.LogInformation(
                "[STUDENT-AD] Cuenta creada. HrStudentId={Id} | Email={Email} | AdObjectId={AdId}",
                req.HrStudentId, email, created.Id);

            await TryAddToGroupAsync(dir, created.Id, req.HrStudentId, ct);

            return new CreateStudentAdAccountResult(true, created.Id, email, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[STUDENT-AD] Error al crear cuenta en AD. HrStudentId={Id}", req.HrStudentId);
            return new CreateStudentAdAccountResult(false, null, email, ex.Message);
        }
    }

    // ── Deshabilitar cuenta ───────────────────────────────────────────────────

    public async Task<DisableStudentAdAccountResult> DisableAdAccountAsync(
        string adObjectId,
        CancellationToken ct = default)
    {
        _logger.LogInformation(
            "[STUDENT-AD] Deshabilitando cuenta AD. AdObjectId={Id}", adObjectId);

        try
        {
            var dir = _resolver.GetDirectory("LocalAd");

            await dir.SetUserEnabledAsync(adObjectId, false);
            _logger.LogInformation("[STUDENT-AD] Cuenta deshabilitada. AdObjectId={Id}", adObjectId);

            if (!string.IsNullOrWhiteSpace(_adOpts.Value.EstudiantesInactivosOu))
            {
                try
                {
                    await dir.MoveUserToOuAsync(adObjectId, _adOpts.Value.EstudiantesInactivosOu, ct);
                    _logger.LogInformation(
                        "[STUDENT-AD] Movido a OU Inactivos. AdObjectId={Id}", adObjectId);
                }
                catch (Exception moveEx)
                {
                    _logger.LogWarning(moveEx,
                        "[STUDENT-AD] No se pudo mover a OU Inactivos. AdObjectId={Id}", adObjectId);
                }
            }

            if (!string.IsNullOrWhiteSpace(_provOpts.Value.GrupoEstudiantesActivosCn))
            {
                try
                {
                    await dir.RemoveUserFromGroupAsync(_provOpts.Value.GrupoEstudiantesActivosCn, adObjectId, ct);
                    _logger.LogInformation(
                        "[STUDENT-AD] Quitado del grupo EActivos. AdObjectId={Id}", adObjectId);
                }
                catch (Exception grpEx)
                {
                    _logger.LogWarning(grpEx,
                        "[STUDENT-AD] No se pudo quitar del grupo EActivos. AdObjectId={Id}", adObjectId);
                }
            }

            return new DisableStudentAdAccountResult(true, adObjectId, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[STUDENT-AD] Error deshabilitando cuenta. AdObjectId={Id}", adObjectId);
            return new DisableStudentAdAccountResult(false, adObjectId, ex.Message);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task TryAddToGroupAsync(IDirectoryService dir, string adObjectId, int hrStudentId, CancellationToken ct)
    {
        var groupCn = _provOpts.Value.GrupoEstudiantesActivosCn;
        if (string.IsNullOrWhiteSpace(groupCn)) return;

        try
        {
            var groups = await dir.ListGroupsAsync(filter: groupCn, ct: ct);
            var group  = groups.FirstOrDefault();
            if (group is not null)
            {
                await dir.AddUserToGroupAsync(group.Id, adObjectId, ct);
                _logger.LogInformation(
                    "[STUDENT-AD] Agregado al grupo {Group}. HrStudentId={Id}", groupCn, hrStudentId);
            }
            else
            {
                _logger.LogWarning("[STUDENT-AD] Grupo '{Group}' no encontrado en AD.", groupCn);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "[STUDENT-AD] No se pudo agregar al grupo {Group}. HrStudentId={Id}", groupCn, hrStudentId);
        }
    }
}
