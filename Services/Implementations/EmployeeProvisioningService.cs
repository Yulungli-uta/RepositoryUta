using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public class EmployeeProvisioningService : IEmployeeProvisioningService
{
    private readonly AuthDbContext _context;
    private readonly IIdentityProviderResolver _resolver;
    private readonly IAzureManagementService _azureMgmt;
    private readonly IMicrosoftLicenseService _licenseService;
    private readonly IInstitutionalEmailGenerator _emailGenerator;
    private readonly IOptions<LocalAdOptions> _adOpts;
    private readonly IOptions<ProvisioningOptions> _provOpts;
    private readonly ILogger<EmployeeProvisioningService> _logger;

    private const int BulkMaxConcurrency = 5;
    private const int CompletePendingConcurrency = 3;

    public EmployeeProvisioningService(
        AuthDbContext context,
        IIdentityProviderResolver resolver,
        IAzureManagementService azureMgmt,
        IMicrosoftLicenseService licenseService,
        IInstitutionalEmailGenerator emailGenerator,
        IOptions<LocalAdOptions> adOpts,
        IOptions<ProvisioningOptions> provOpts,
        ILogger<EmployeeProvisioningService> logger)
    {
        _context        = context;
        _resolver       = resolver;
        _azureMgmt      = azureMgmt;
        _licenseService = licenseService;
        _emailGenerator = emailGenerator;
        _adOpts         = adOpts;
        _provOpts       = provOpts;
        _logger         = logger;
    }

    // ── Aprovisionamiento individual ──────────────────────────────────────────

    public async Task<UserProvisioningDto> ProvisionAsync(ProvisionEmployeeRequest req, CancellationToken ct = default)
    {
        _logger.LogInformation(
            "[PROVISIONING] Iniciando aprovisionamiento. HrEmployeeId={HrEmployeeId} | GivenName={GivenName} | Surname={Surname} | PersonalEmail={PersonalEmail}",
            req.HrEmployeeId, req.GivenName, req.Surname, req.PersonalEmail ?? "(no proporcionado)");

        // Generar el email institucional desde nombre+apellido
        string institutionalEmail;
        try
        {
            institutionalEmail = await _emailGenerator.GenerateAvailableEmailAsync(
                req.HrEmployeeId, req.GivenName, req.Surname, ct);
            _logger.LogInformation(
                "[PROVISIONING] Email institucional generado: {InstitutionalEmail} para HrEmployeeId={HrEmployeeId}",
                institutionalEmail, req.HrEmployeeId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[PROVISIONING] ERROR al generar email institucional para HrEmployeeId={HrEmployeeId}",
                req.HrEmployeeId);
            throw;
        }

        req = req with { Email = institutionalEmail };

        // Verificar duplicados: si ya existe una cuenta activa (no en estado *Failed) se rechaza con 409
        var existing = await _context.UserProvisionings
            .Where(p => (p.HrEmployeeId == req.HrEmployeeId || p.Email == req.Email)
                     && p.ProvisioningStatusId != (int)ProvisioningStatus.LocalAdFailed
                     && p.ProvisioningStatusId != (int)ProvisioningStatus.LicenseFailed)
            .OrderByDescending(p => p.CreatedAt)
            .FirstOrDefaultAsync(ct);

        if (existing is not null)
        {
            _logger.LogInformation(
                "[PROVISIONING] Duplicado detectado. Empleado {EmployeeId} ({Email}) ya tiene aprovisionamiento activo id={ProvId} en estado {Status}",
                req.HrEmployeeId, existing.Email, existing.Id, existing.ProvisioningStatusName);
            throw new DuplicateProvisioningException(
                existing.HrEmployeeId, existing.Email, existing.ProvisioningStatusName ?? "Desconocido");
        }

        _logger.LogInformation(
            "[PROVISIONING] Creando registro en tbl_UserProvisionings. Email institucional={InstitutionalEmail} | PersonalEmail={PersonalEmail}",
            institutionalEmail, req.PersonalEmail ?? "(vacío)");

        var record = CreateInitialRecord(req);
        _context.UserProvisionings.Add(record);
        await _context.SaveChangesAsync(ct);

        _logger.LogInformation(
            "[PROVISIONING] Registro guardado. ProvisioningId={ProvisioningId} | Email={Email} — Iniciando creación en AD...",
            record.Id, record.Email);

        await DoProvisionAsync(record, req, ct);

        _logger.LogInformation(
            "[PROVISIONING] Resultado final. ProvisioningId={ProvisioningId} | Status={Status} | Error={Error}",
            record.Id, record.ProvisioningStatusName, record.ErrorMessage ?? "ninguno");

        return MapToDto(record);
    }

    public async Task<IReadOnlyList<BulkProvisioningResult>> ProvisionBulkAsync(
        IEnumerable<ProvisionEmployeeRequest> requests,
        CancellationToken ct = default)
    {
        var list = requests.ToList();
        var results = new BulkProvisioningResult[list.Count];
        using var semaphore = new SemaphoreSlim(BulkMaxConcurrency, BulkMaxConcurrency);

        var tasks = list.Select(async (req, idx) =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                var dto = await ProvisionAsync(req, ct);
                results[idx] = new BulkProvisioningResult(req.HrEmployeeId, dto.Email, true, dto, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error en bulk provisioning para empleado {EmployeeId}", req.HrEmployeeId);
                results[idx] = new BulkProvisioningResult(req.HrEmployeeId, req.Email ?? string.Empty, false, null, ex.Message);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    // ── Consulta / listado ────────────────────────────────────────────────────

    public async Task<UserProvisioningDto?> GetStatusAsync(Guid id, CancellationToken ct = default)
    {
        var record = await _context.UserProvisionings.FindAsync([id], ct);
        return record is null ? null : MapToDto(record);
    }

    public async Task<PagedResult<UserProvisioningDto>> ListAsync(
        int page, int pageSize, int? statusId = null, CancellationToken ct = default)
    {
        var query = _context.UserProvisionings.AsQueryable();
        if (statusId.HasValue)
            query = query.Where(p => p.ProvisioningStatusId == statusId.Value);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(p => p.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

        return PagedResult<UserProvisioningDto>.Create(items.Select(MapToDto).ToList(), page, pageSize, total);
    }

    // ── Reintento ─────────────────────────────────────────────────────────────

    public async Task<UserProvisioningDto?> RetryAsync(Guid id, string? newInitialPassword = null, CancellationToken ct = default)
    {
        var record = await _context.UserProvisionings.FindAsync([id], ct);
        if (record is null) return null;

        // Fase 3: para LicenseFailed no hay que recriar en AD — delegar al flujo de completado
        if (record.ProvisioningStatusId == (int)ProvisioningStatus.LicenseFailed)
        {
            _logger.LogInformation(
                "Aprovisionamiento {Id}: LicenseFailed — reintentando solo asignación de licencia.", id);
            return await CheckAndCompleteProvisioningAsync(id, ct);
        }

        if (record.ProvisioningStatusId != (int)ProvisioningStatus.LocalAdFailed)
        {
            _logger.LogWarning(
                "Aprovisionamiento {Id} no está en estado retryable (status={Status})", id, record.ProvisioningStatusId);
            return MapToDto(record);
        }

        // LocalAdFailed: se necesita una contraseña válida para recriar en AD
        if (string.IsNullOrWhiteSpace(newInitialPassword))
            throw new InvalidOperationException(
                "Se debe proporcionar una nueva contraseña inicial para reintentar la creación de cuenta en AD Local.");

        var req = new ProvisionEmployeeRequest(
            HrEmployeeId:    record.HrEmployeeId,
            DisplayName:     record.DisplayName,
            GivenName:       record.GivenName ?? string.Empty,
            Surname:         record.Surname ?? string.Empty,
            InitialPassword: newInitialPassword,
            EmployeeTypeId:  record.EmployeeTypeId,
            EmployeeTypeName: record.EmployeeTypeName,
            DepartmentId:    record.DepartmentId,
            DepartmentName:  record.DepartmentName,
            JobTitle:        record.JobTitle,
            SourceReference: record.SourceReference,
            Email:           record.Email); // email del registro anterior (ya es institucional)

        record.ProvisioningStatusId = (int)ProvisioningStatus.Requested;
        record.ProvisioningStatusName = nameof(ProvisioningStatus.Requested);
        record.ErrorMessage = null;
        record.UpdatedAt = DateTime.Now;
        await _context.SaveChangesAsync(ct);

        await DoProvisionAsync(record, req, ct);
        return MapToDto(record);
    }

    // ── Lógica interna ────────────────────────────────────────────────────────

    /// <summary>
    /// Orquesta: crea usuario en AD Local, registra en auth DB y verifica sync Entra.
    /// Los errores en cada paso actualizan el status del record en lugar de lanzar al caller.
    /// </summary>
    private async Task DoProvisionAsync(UserProvisioning record, ProvisionEmployeeRequest req, CancellationToken ct)
    {
        await using var tx = await _context.Database.BeginTransactionAsync(ct);
        try
        {
            var dir = _resolver.GetDirectory("LocalAd");

            // 1. Validar dominio
            var domain = GetExpectedDomain();
            var email = req.Email ?? throw new InvalidOperationException("No se generó correo institucional.");

            if (!string.IsNullOrWhiteSpace(domain) &&
                !email.EndsWith($"@{domain}", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"El correo debe usar el dominio institucional @{domain}");

            // 2. Crear usuario en AD Local en la OU de funcionarios activos
            var funcionariosActivosOu = _adOpts.Value.FuncionariosActivosOu;
            if (string.IsNullOrWhiteSpace(funcionariosActivosOu))
                throw new InvalidOperationException(
                    "LocalAd:FuncionariosActivosOu no está configurado en appsettings.json.");

            var dirUser = new DirectoryUser(
                string.Empty, email, req.DisplayName,
                req.GivenName, req.Surname, req.JobTitle, req.DepartmentName,
                AccountEnabled: true, CreatedDateTime: null,
                IdCard: req.IdCard);

            DirectoryUser created;
            try
            {
                created = await dir.CreateUserAsync(dirUser, req.InitialPassword, funcionariosActivosOu, req.ForcePasswordChange, ct);
            }
            catch (Exception adEx)
            {
                _logger.LogError(adEx, "Error creando usuario en AD Local: {Email}", email);
                // Fase 2: rollback primero para no dejar la tx colgada; luego persistir el fallo fuera de ella
                await tx.RollbackAsync(ct);
                await UpdateStatusAsync(record, ProvisioningStatus.LocalAdFailed, adEx.Message, ct);
                return;
            }

            record.LocalAdObjectId = created.Id;
            record.ProvisionedAt   = DateTime.Now;

            // Si el CN tuvo que ajustarse por conflicto, se persiste como aviso (no como error)
            // El estado sigue siendo CreatedInLocalAd — la cuenta fue creada correctamente
            if (!string.IsNullOrWhiteSpace(created.CnWarning))
            {
                _logger.LogWarning(
                    "[PROVISIONING] ⚠ CN ajustado en AD Local. HrEmployeeId={HrEmployeeId} | {Warning}",
                    req.HrEmployeeId, created.CnWarning);
                record.ErrorMessage = $"[AVISO] {created.CnWarning}";
            }

            await UpdateStatusAsync(record, ProvisioningStatus.CreatedInLocalAd, record.ErrorMessage, ct);

            // 3. Crear auth.tbl_Users (UserType = AzureAD — el empleado autenticará via Entra SSO)
            var authUser = await EnsureAuthUserAsync(email, req.DisplayName, ct);
            record.AuthUserId = authUser.Id;
            _logger.LogInformation("[PROVISIONING] auth.tbl_Users: UserId={UserId} | Email={Email} | DisplayName='{DisplayName}'",
                authUser.Id, email, req.DisplayName);

            // 4. Crear auth.tbl_UserEmployees (punto de unión con HR)
            await EnsureUserEmployeeAsync(authUser.Id, email, req.HrEmployeeId, ct);
            _logger.LogInformation("[PROVISIONING] auth.tbl_UserEmployees: UserId={UserId} | HrEmployeeId={HrEmployeeId} | EmployeeEmail={Email}",
                authUser.Id, req.HrEmployeeId, email);

            // 5. Asignar rol básico desde configuración (Provisioning:DefaultRoleName)
            await EnsureDefaultRoleAsync(authUser.Id, ct);

            // 6. Agregar a grupo AD Local desde configuración (Provisioning:DefaultAdGroupId)
            await EnsureDefaultAdGroupAsync(dir, created.Id, email, ct);

            await _context.SaveChangesAsync(ct);

            // 7. Verificar sync Entra ID (puede ser PendingSync o Synced si ya sincronizó)
            try
            {
                var sync = await _azureMgmt.CheckUserEntraSyncAsync(email);

                if (sync.Status == EntraSyncStatus.Synced || sync.Status == EntraSyncStatus.Disabled)
                {
                    record.EntraObjectId = sync.AzureObjectId;
                    await UpdateStatusAsync(record, ProvisioningStatus.SyncedInEntra, null, ct);
                }
                else
                {
                    await UpdateStatusAsync(record, ProvisioningStatus.PendingEntraSync, sync.Message, ct);
                }
            }
            catch (Exception syncEx)
            {
                // No es error crítico — el AD Local ya está creado; marcar PendingSync
                _logger.LogWarning(syncEx, "No se pudo verificar Entra sync para {Email}", email);
                await UpdateStatusAsync(record, ProvisioningStatus.PendingEntraSync, "Verificación de Entra sync pendiente", ct);
            }

            await tx.CommitAsync(ct);
            _logger.LogInformation("Aprovisionamiento completado para empleado {EmployeeId} ({Email}) — status: {Status}",
                req.HrEmployeeId, email, record.ProvisioningStatusName);
        }
        catch (Exception ex)
        {
            await tx.RollbackAsync(ct);
            _logger.LogError(ex, "Error inesperado en aprovisionamiento de empleado {EmployeeId}", req.HrEmployeeId);
            await UpdateStatusAsync(record, ProvisioningStatus.LocalAdFailed, ex.Message, ct);
        }
    }

    /// <summary>
    /// Asigna el rol básico configurado en <c>Provisioning:DefaultRoleName</c> al usuario recién creado.
    /// Solo aplica si el usuario no tiene ya ese rol. No falla el aprovisionamiento si el rol no existe.
    /// </summary>
    /// <summary>
    /// Asigna todos los roles configurados en <c>Provisioning:DefaultRoleNames</c>
    /// al usuario recién creado. Por cada rol:
    ///   - Si no existe en auth.tbl_Roles → LogError + continúa con el siguiente
    ///   - Si el usuario ya lo tiene → lo omite silenciosamente
    ///   - Si es nuevo → inserta en auth.tbl_UserRoles
    /// No lanza excepción: un rol faltante no detiene el aprovisionamiento.
    /// </summary>
    private async Task EnsureDefaultRoleAsync(Guid userId, CancellationToken ct)
    {
        var roleNames = _provOpts.Value.DefaultRoleNames;

        if (roleNames is null || roleNames.Length == 0)
        {
            _logger.LogWarning(
                "[PROVISIONING] Provisioning:DefaultRoleNames vacío — se omite asignación de roles.");
            return;
        }

        _logger.LogInformation(
            "[PROVISIONING] Asignando {Count} rol(es) a UserId={UserId}: [{Roles}]",
            roleNames.Length, userId, string.Join(", ", roleNames));

        foreach (var roleName in roleNames)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                continue;

            var role = await _context.Roles
                .Where(r => r.Name == roleName && r.IsActive && !r.IsDeleted)
                .Select(r => new { r.Id, r.Name })
                .FirstOrDefaultAsync(ct);

            if (role is null)
            {
                _logger.LogError(
                    "[PROVISIONING] ✗ Rol '{RoleName}' no encontrado en auth.tbl_Roles. " +
                    "Verifica Provisioning:DefaultRoleNames en appsettings.json. UserId={UserId}",
                    roleName, userId);
                continue;
            }

            var alreadyAssigned = await _context.UserRoles
                .AnyAsync(ur => ur.UserId == userId && ur.RoleId == role.Id && !ur.IsDeleted, ct);

            if (alreadyAssigned)
            {
                _logger.LogInformation(
                    "[PROVISIONING] Rol '{RoleName}' ya asignado a UserId={UserId} — omitido.",
                    roleName, userId);
                continue;
            }

            _context.UserRoles.Add(new UserRole
            {
                UserId     = userId,
                RoleId     = role.Id,
                AssignedAt = DateTime.Now,
                AssignedBy = "Provisioning-Automatico",
                Reason     = "Asignación automática al aprovisionar cuenta institucional"
            });

            _logger.LogInformation(
                "[PROVISIONING] ✓ auth.tbl_UserRoles: RoleId={RoleId} ('{RoleName}') → UserId={UserId}",
                role.Id, role.Name, userId);
        }
    }

    /// <summary>
    /// Agrega el funcionario al grupo de AD Local configurado en <c>Provisioning:GrupoFuncionariosActivosCn</c>.
    /// No falla el aprovisionamiento si el grupo no existe o la operación falla.
    /// </summary>
    private async Task EnsureDefaultAdGroupAsync(
        IDirectoryService dir, string adObjectId, string email, CancellationToken ct)
    {
        var groupId = _provOpts.Value.GrupoFuncionariosActivosCn;

        if (string.IsNullOrWhiteSpace(groupId))
        {
            _logger.LogInformation("[PROVISIONING] Provisioning:GrupoFuncionariosActivosCn vacío — no se agrega a grupo AD.");
            return;
        }

        _logger.LogInformation(
            "[PROVISIONING] Agregando funcionario '{Email}' (AD ObjectId={AdObjectId}) al grupo '{GroupId}'...",
            email, adObjectId, groupId);

        try
        {
            var alreadyInGroup = await dir.IsUserInGroupAsync(groupId, adObjectId, ct);
            if (alreadyInGroup)
            {
                _logger.LogInformation(
                    "[PROVISIONING] Usuario '{Email}' ya pertenece al grupo '{GroupId}' — se omite.",
                    email, groupId);
                return;
            }

            await dir.AddUserToGroupAsync(groupId, adObjectId, ct);

            _logger.LogInformation(
                "[PROVISIONING] ✓ AD Local: '{Email}' agregado al grupo '{GroupId}'",
                email, groupId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "[PROVISIONING] ✗ ERROR al agregar '{Email}' al grupo AD '{GroupId}'. " +
                "El aprovisionamiento continúa — revisa la configuración del grupo.",
                email, groupId);
        }
    }

    private async Task<User> EnsureAuthUserAsync(string email, string displayName, CancellationToken ct)
    {
        var existing = await _context.Users.FirstOrDefaultAsync(u => u.Email == email, ct);
        if (existing is not null) return existing;

        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = email,
            DisplayName = displayName,
            UserType = "AzureAD",
            IsActive = true,
            CreatedAt = DateTime.Now
        };
        _context.Users.Add(user);
        await _context.SaveChangesAsync(ct);
        return user;
    }

    private async Task EnsureUserEmployeeAsync(Guid userId, string email, int hrEmployeeId, CancellationToken ct)
    {
        var exists = await _context.UserEmployees.AnyAsync(ue => ue.EmployeeEmail == email, ct);
        if (exists) return;

        _context.UserEmployees.Add(new UserEmployee
        {
            UserId = userId,
            EmployeeEmail = email,
            HrEmployeeId = hrEmployeeId,
            IsActive = true,
            SyncDate = DateTime.Now,
            Notes = $"Aprovisionado desde HrSystem (EmployeeId={hrEmployeeId})"
        });
        await _context.SaveChangesAsync(ct);
    }

    public async Task<DisableEmployeeResult> DisableEmployeeAsync(int hrEmployeeId, CancellationToken ct = default)
    {
        _logger.LogInformation("[DISABLE] Iniciando deshabilitar cuenta. HrEmployeeId={HrEmployeeId}", hrEmployeeId);

        var userEmployee = await _context.UserEmployees
            .FirstOrDefaultAsync(ue => ue.HrEmployeeId == hrEmployeeId && ue.IsActive, ct);

        if (userEmployee is null)
        {
            _logger.LogWarning("[DISABLE] No se encontró cuenta activa para HrEmployeeId={HrEmployeeId}", hrEmployeeId);
            return new DisableEmployeeResult(false, hrEmployeeId, null,
                "No se encontró cuenta activa para este empleado.");
        }

        var user = await _context.Users.FindAsync([userEmployee.UserId], ct);
        if (user is null)
        {
            _logger.LogWarning("[DISABLE] auth.tbl_Users no encontrado para UserId={UserId}", userEmployee.UserId);
            return new DisableEmployeeResult(false, hrEmployeeId, userEmployee.EmployeeEmail,
                "Usuario no encontrado en auth.tbl_Users.");
        }

        // Obtener el LocalAdObjectId (GUID) desde el registro de aprovisionamiento
        var provisioning = await _context.UserProvisionings
            .Where(p => p.HrEmployeeId == hrEmployeeId && !string.IsNullOrWhiteSpace(p.LocalAdObjectId))
            .OrderByDescending(p => p.ProvisionedAt)
            .FirstOrDefaultAsync(ct);

        var adIdentifier = provisioning?.LocalAdObjectId ?? userEmployee.EmployeeEmail;

        // Determinar si es estudiante para elegir OU y grupo correcto
        var studentTypeIds = _provOpts.Value.StudentEmployeeTypeIds;
        bool isStudent = provisioning is not null
            && studentTypeIds is { Length: > 0 }
            && studentTypeIds.Contains(provisioning.EmployeeTypeId);

        var inactivosOu = isStudent
            ? _adOpts.Value.EstudiantesInactivosOu
            : _adOpts.Value.FuncionariosInactivosOu;

        var grupoActivos = isStudent
            ? _provOpts.Value.GrupoEstudiantesActivosCn
            : _provOpts.Value.GrupoFuncionariosActivosCn;

        var tipoPersona = isStudent ? "estudiante" : "funcionario";

        try
        {
            var dir = _resolver.GetDirectory("LocalAd");

            // 1. Deshabilitar cuenta
            await dir.SetUserEnabledAsync(adIdentifier, false);
            _logger.LogInformation("[DISABLE] Cuenta deshabilitada en AD ({Tipo}). Identifier={Id}", tipoPersona, adIdentifier);

            // 2. Mover a OU Inactivos (funcionarios o estudiantes según tipo)
            if (!string.IsNullOrWhiteSpace(inactivosOu))
            {
                try
                {
                    await dir.MoveUserToOuAsync(adIdentifier, inactivosOu, ct);
                    _logger.LogInformation("[DISABLE] Usuario movido a OU Inactivos ({Ou}). Identifier={Id}", inactivosOu, adIdentifier);
                }
                catch (Exception moveEx)
                {
                    _logger.LogWarning(moveEx, "[DISABLE] No se pudo mover a OU Inactivos ({Ou}). Identifier={Id}", inactivosOu, adIdentifier);
                }
            }
            else
            {
                _logger.LogWarning("[DISABLE] OU Inactivos no configurada para tipo '{Tipo}' — se omite movimiento.", tipoPersona);
            }

            // 3. Quitar del grupo activo (UActivos o EActivos según tipo)
            if (!string.IsNullOrWhiteSpace(grupoActivos))
            {
                try
                {
                    await dir.RemoveUserFromGroupAsync(grupoActivos, adIdentifier, ct);
                    _logger.LogInformation("[DISABLE] Usuario quitado del grupo {Group}. Identifier={Id}", grupoActivos, adIdentifier);
                }
                catch (Exception grpEx)
                {
                    _logger.LogWarning(grpEx, "[DISABLE] No se pudo quitar del grupo {Group}. Identifier={Id}", grupoActivos, adIdentifier);
                }
            }
        }
        catch (Exception adEx)
        {
            _logger.LogError(adEx, "[DISABLE] Error al deshabilitar en AD Local. Identifier={Id}", adIdentifier);
            return new DisableEmployeeResult(false, hrEmployeeId, userEmployee.EmployeeEmail,
                $"Error en AD Local: {adEx.Message}");
        }

        user.IsActive = false;
        await _context.SaveChangesAsync(ct);

        _logger.LogInformation("[DISABLE] ✓ Cuenta deshabilitada. HrEmployeeId={HrEmployeeId} | Email={Email}",
            hrEmployeeId, userEmployee.EmployeeEmail);

        return new DisableEmployeeResult(true, hrEmployeeId, userEmployee.EmployeeEmail, null);
    }

    public async Task<DisableEmployeeResult?> DisableByProvisioningIdAsync(Guid provisioningId, CancellationToken ct = default)
    {
        var provisioning = await _context.UserProvisionings
            .FirstOrDefaultAsync(p => p.Id == provisioningId, ct);

        if (provisioning is null)
        {
            _logger.LogWarning("[DISABLE] Registro de aprovisionamiento no encontrado. ProvisioningId={Id}", provisioningId);
            return null;
        }

        return await DisableEmployeeAsync(provisioning.HrEmployeeId, ct);
    }

    public async Task<DisableEmployeeResult?> DisableByAdIdAsync(string adObjectId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(adObjectId))
            return null;

        var provisioning = await _context.UserProvisionings
            .Where(p => p.LocalAdObjectId == adObjectId)
            .OrderByDescending(p => p.ProvisionedAt)
            .FirstOrDefaultAsync(ct);

        if (provisioning is null)
        {
            _logger.LogWarning("[DISABLE] Sin registro de aprovisionamiento para AD ObjectId={Id}", adObjectId);
            return null;
        }

        return await DisableEmployeeAsync(provisioning.HrEmployeeId, ct);
    }

    private async Task UpdateStatusAsync(
        UserProvisioning record,
        ProvisioningStatus status,
        string? message,
        CancellationToken ct)
    {
        record.ProvisioningStatusId = (int)status;
        record.ProvisioningStatusName = status.ToString();
        record.ErrorMessage = message;
        record.UpdatedAt = DateTime.Now;
        record.LastCheckedAt = DateTime.Now;
        await _context.SaveChangesAsync(ct);
    }

    private string GetExpectedDomain()
    {
        var domain = string.Join(".", _adOpts.Value.BaseDn
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
            .Select(p => p[3..]));

        // Mismo fallback que InstitutionalEmailGenerator para garantizar consistencia
        return string.IsNullOrWhiteSpace(domain) ? "uta.edu.ec" : domain.ToLowerInvariant();
    }

    private static UserProvisioning CreateInitialRecord(ProvisionEmployeeRequest req) => new()
    {
        Id = Guid.NewGuid(),
        HrEmployeeId = req.HrEmployeeId,
        Email = req.Email!,
        DisplayName = req.DisplayName,
        GivenName = req.GivenName,
        Surname = req.Surname,
        DepartmentId = req.DepartmentId,
        DepartmentName = req.DepartmentName,
        JobTitle = req.JobTitle,
        EmployeeTypeId = req.EmployeeTypeId,
        EmployeeTypeName = req.EmployeeTypeName,
        ProvisioningStatusId = (int)ProvisioningStatus.Requested,
        ProvisioningStatusName = nameof(ProvisioningStatus.Requested),
        SourceReference = req.SourceReference,
        CreatedAt = DateTime.Now
    };

    // ── Completar aprovisionamiento (Entra sync → licencia) ───────────────────

    public async Task<UserProvisioningDto?> CheckAndCompleteProvisioningAsync(Guid id, CancellationToken ct = default)
    {
        var record = await _context.UserProvisionings.FindAsync([id], ct);
        if (record is null) return null;

        var completableStatuses = new[]
        {
            (int)ProvisioningStatus.PendingEntraSync,
            (int)ProvisioningStatus.SyncedInEntra,
            (int)ProvisioningStatus.LicenseFailed
        };

        if (!completableStatuses.Contains(record.ProvisioningStatusId))
        {
            _logger.LogInformation("Aprovisionamiento {Id} ya está en status final: {Status}", id, record.ProvisioningStatusName);
            return MapToDto(record);
        }

        await DoCompleteAsync(record, ct);
        return MapToDto(record);
    }

    public async Task<CompletePendingResult> CompletePendingAsync(CancellationToken ct = default)
    {
        var pendingStatuses = new[]
        {
            (int)ProvisioningStatus.PendingEntraSync,
            (int)ProvisioningStatus.SyncedInEntra,
            (int)ProvisioningStatus.LicenseFailed
        };

        var records = await _context.UserProvisionings
            .Where(p => pendingStatuses.Contains(p.ProvisioningStatusId))
            .OrderBy(p => p.CreatedAt)
            .ToListAsync(ct);

        if (records.Count == 0)
            return new CompletePendingResult(0, 0, 0, 0, []);

        _logger.LogInformation("CompletePending: procesando {Count} registros pendientes", records.Count);

        using var semaphore = new SemaphoreSlim(CompletePendingConcurrency, CompletePendingConcurrency);
        var tasks = records.Select(async record =>
        {
            await semaphore.WaitAsync(ct);
            try { await DoCompleteAsync(record, ct); }
            finally { semaphore.Release(); }
        });

        await Task.WhenAll(tasks);

        var results = records.Select(MapToDto).ToList();
        return new CompletePendingResult(
            TotalProcessed: results.Count,
            LicenseAssigned: results.Count(r => r.ProvisioningStatusId == (int)ProvisioningStatus.LicenseAssigned),
            StillPending: results.Count(r => r.ProvisioningStatusId == (int)ProvisioningStatus.PendingEntraSync),
            Failed: results.Count(r => r.ProvisioningStatusId == (int)ProvisioningStatus.LicenseFailed),
            Results: results
        );
    }

    /// <summary>
    /// Núcleo del completado: verifica sync Entra → asigna licencia O365.
    /// Actualiza el record en la BD en cada paso.
    /// </summary>
    private async Task DoCompleteAsync(UserProvisioning record, CancellationToken ct)
    {
        record.LastCheckedAt = DateTime.Now;
        record.UpdatedAt = DateTime.Now;

        // 1. Verificar estado de sincronización en Entra
        EntraSyncResult sync;
        try
        {
            sync = await _azureMgmt.CheckUserEntraSyncAsync(record.Email);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error al verificar Entra sync para {Email}", record.Email);
            record.ErrorMessage = $"Error al verificar Entra sync: {ex.Message}";
            await _context.SaveChangesAsync(ct);
            return;
        }

        // 2. Si aún no sincronizó, actualizar timestamp y salir
        if (sync.Status == EntraSyncStatus.PendingSync || sync.Status == EntraSyncStatus.Unknown)
        {
            record.ProvisioningStatusId = (int)ProvisioningStatus.PendingEntraSync;
            record.ProvisioningStatusName = nameof(ProvisioningStatus.PendingEntraSync);
            record.ErrorMessage = sync.Message;
            await _context.SaveChangesAsync(ct);
            _logger.LogInformation("Empleado {Email} aún pendiente de sync Entra", record.Email);
            return;
        }

        // 3. Ya sincronizó — actualizar estado y EntraObjectId
        if (!string.IsNullOrWhiteSpace(sync.AzureObjectId))
            record.EntraObjectId = sync.AzureObjectId;

        record.ProvisioningStatusId = (int)ProvisioningStatus.SyncedInEntra;
        record.ProvisioningStatusName = nameof(ProvisioningStatus.SyncedInEntra);
        record.ErrorMessage = null;
        await _context.SaveChangesAsync(ct);

        _logger.LogInformation("Empleado {Email} sincronizado en Entra. Procediendo a asignar licencia.", record.Email);

        // 4. Asignar licencia O365 estándar (todos los empleados usan el mismo SKU)
        LicenseOperationResult licenseResult;
        try
        {
            licenseResult = await _licenseService.AssignEmployeeLicenseAsync(record.Email, countryCode: "EC", ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Excepción al asignar licencia para {Email}", record.Email);
            record.ProvisioningStatusId = (int)ProvisioningStatus.LicenseFailed;
            record.ProvisioningStatusName = nameof(ProvisioningStatus.LicenseFailed);
            record.ErrorMessage = ex.Message;
            await _context.SaveChangesAsync(ct);
            return;
        }

        // 5. Registrar resultado
        if (licenseResult.Success)
        {
            record.LicenseSkuId = licenseResult.SkuPartNumber;
            record.LicenseAssignedAt = DateTime.Now;
            record.ProvisioningStatusId = (int)ProvisioningStatus.LicenseAssigned;
            record.ProvisioningStatusName = nameof(ProvisioningStatus.LicenseAssigned);
            record.ErrorMessage = null;
            _logger.LogInformation("Licencia {Sku} asignada a {Email}", licenseResult.SkuPartNumber, record.Email);
        }
        else
        {
            record.ProvisioningStatusId = (int)ProvisioningStatus.LicenseFailed;
            record.ProvisioningStatusName = nameof(ProvisioningStatus.LicenseFailed);
            record.ErrorMessage = licenseResult.Message;
            _logger.LogWarning("Fallo al asignar licencia a {Email}: {Error}", record.Email, licenseResult.Message);
        }

        record.UpdatedAt = DateTime.Now;
        await _context.SaveChangesAsync(ct);
    }

    // ── Restablecimiento de contraseña ───────────────────────────────────────

    public async Task<PasswordResetResult?> ResetPasswordAsync(Guid id, CancellationToken ct = default)
    {
        var record = await _context.UserProvisionings
            .FirstOrDefaultAsync(p => p.Id == id, ct);

        if (record is null) return null;

        if (string.IsNullOrWhiteSpace(record.LocalAdObjectId))
            throw new InvalidOperationException(
                $"El empleado no tiene cuenta en AD Local (aprovisionamiento id={id}).");

        var dir = _resolver.GetDirectory("LocalAd");
        var newPassword = GenerateTemporaryPassword();

        await dir.ChangeUserPasswordAsync(record.LocalAdObjectId, newPassword, forcePasswordChange: true, ct);

        record.UpdatedAt = DateTime.Now;
        await _context.SaveChangesAsync(ct);

        _logger.LogInformation(
            "Contraseña restablecida en AD Local para EmpleadoHR={EmployeeId}, Email={Email}",
            record.HrEmployeeId, record.Email);

        return new PasswordResetResult(
            ProvisioningId:       record.Id,
            HrEmployeeId:         record.HrEmployeeId,
            Email:                record.Email,
            NewTemporaryPassword: newPassword,
            Message:              "Contraseña restablecida en AD Local. El usuario deberá cambiarla en el próximo inicio de sesión."
        );
    }

    private static string GenerateTemporaryPassword()
    {
        const string upper  = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower  = "abcdefghjkmnpqrstuvwxyz";
        const string digits = "23456789";
        const string special = "!@#$%&*";

        var rng = Random.Shared;
        var chars = new char[12];
        chars[0] = upper[rng.Next(upper.Length)];
        chars[1] = lower[rng.Next(lower.Length)];
        chars[2] = digits[rng.Next(digits.Length)];
        chars[3] = special[rng.Next(special.Length)];
        const string all = upper + lower + digits + special;
        for (int i = 4; i < chars.Length; i++)
            chars[i] = all[rng.Next(all.Length)];
        // Mezclar para evitar posiciones predecibles
        for (int i = chars.Length - 1; i > 0; i--)
        {
            int j = rng.Next(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }

    private static UserProvisioningDto MapToDto(UserProvisioning p)
    {
        // Separar avisos ([AVISO] ...) de errores reales para que el frontend
        // pueda diferenciar entre "algo salió mal" y "completado con advertencia"
        string? errorMessage = p.ErrorMessage;
        string? warning      = null;

        if (p.ErrorMessage?.StartsWith("[AVISO]", StringComparison.OrdinalIgnoreCase) == true)
        {
            warning      = p.ErrorMessage[7..].Trim(); // extrae el texto sin el prefijo [AVISO]
            errorMessage = null;                        // no es un error — limpiar el campo
        }

        return new(
            p.Id, p.HrEmployeeId, p.Email, p.DisplayName,
            p.GivenName, p.Surname, p.DepartmentId, p.DepartmentName,
            p.JobTitle, p.EmployeeTypeId, p.EmployeeTypeName,
            p.ProvisioningStatusId, p.ProvisioningStatusName,
            p.AuthUserId, p.LocalAdObjectId, p.EntraObjectId, p.LicenseSkuId,
            p.ProvisionedAt, p.LicenseAssignedAt, p.LastCheckedAt,
            errorMessage, p.RequestedBy, p.SourceReference,
            p.CreatedAt, p.UpdatedAt,
            Warning: warning);
    }
}
