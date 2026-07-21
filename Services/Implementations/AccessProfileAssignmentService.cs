using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

/// <summary>
/// Expande/retrae la asignación de un AccessProfile a un usuario en filas concretas de
/// UserRole, reutilizando ICrudService&lt;UserRole,...&gt; (UserRoleService) para no duplicar
/// la lógica de reactivación/soft-delete/historial ya existente para roles individuales.
/// </summary>
public class AccessProfileAssignmentService : IAccessProfileAssignmentService
{
    private readonly AuthDbContext _db;
    private readonly IGenericRepository<UserAccessProfile> _userProfileRepo;
    private readonly ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> _userRoles;

    public AccessProfileAssignmentService(
        AuthDbContext db,
        IGenericRepository<UserAccessProfile> userProfileRepo,
        ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> userRoles)
    {
        _db = db;
        _userProfileRepo = userProfileRepo;
        _userRoles = userRoles;
    }

    public async Task<List<AccessProfile>> GetAssignedProfilesAsync(Guid userId, CancellationToken ct = default)
    {
        return await (
            from up in _db.UserAccessProfiles.AsNoTracking()
            join p in _db.AccessProfiles.AsNoTracking() on up.AccessProfileId equals p.Id
            where up.UserId == userId && !up.IsDeleted && p.IsActive && !p.IsDeleted
            select p
        ).ToListAsync(ct);
    }

    public async Task AssignAsync(Guid userId, int accessProfileId, string? assignedBy, CancellationToken ct = default)
    {
        var profile = await _db.AccessProfiles.FirstOrDefaultAsync(p => p.Id == accessProfileId && !p.IsDeleted, ct)
            ?? throw new KeyNotFoundException($"AccessProfile {accessProfileId} no existe.");

        var roleIds = await _db.AccessProfileRoles
            .Where(pr => pr.AccessProfileId == accessProfileId)
            .Select(pr => pr.RoleId)
            .ToListAsync(ct);

        var source = $"Profile:{accessProfileId}";

        foreach (var roleId in roleIds)
        {
            try
            {
                await _userRoles.CreateAsync(new CreateUserRoleDto(
                    UserId: userId,
                    RoleId: roleId,
                    ExpiresAt: null,
                    AssignedBy: assignedBy,
                    Reason: $"Perfil: {profile.Name}",
                    AssignedVia: source));
            }
            catch (InvalidOperationException)
            {
                // El usuario ya tiene este rol activo (asignado directo o por otro perfil).
                // No se duplica ni se sobreescribe su origen.
            }
        }

        var existingAssignment = await _userProfileRepo.GetAsync(userId, accessProfileId);
        if (existingAssignment is null)
        {
            await _userProfileRepo.AddAsync(new UserAccessProfile
            {
                UserId = userId,
                AccessProfileId = accessProfileId,
                AssignedBy = assignedBy
            });
        }
        else if (existingAssignment.IsDeleted)
        {
            existingAssignment.IsDeleted = false;
            existingAssignment.AssignedAt = DateTime.Now;
            existingAssignment.AssignedBy = assignedBy;
            await _userProfileRepo.UpdateAsync(existingAssignment);
        }
    }

    public async Task UnassignAsync(Guid userId, int accessProfileId, string? removedBy, CancellationToken ct = default)
    {
        var assignment = await _userProfileRepo.GetAsync(userId, accessProfileId);
        if (assignment is null || assignment.IsDeleted) return;

        var roleIds = await _db.AccessProfileRoles
            .Where(pr => pr.AccessProfileId == accessProfileId)
            .Select(pr => pr.RoleId)
            .ToListAsync(ct);

        var source = $"Profile:{accessProfileId}";

        foreach (var roleId in roleIds)
        {
            var coveredByOtherProfile = await (
                from up in _db.UserAccessProfiles
                where up.UserId == userId && !up.IsDeleted && up.AccessProfileId != accessProfileId
                join pr in _db.AccessProfileRoles on up.AccessProfileId equals pr.AccessProfileId
                where pr.RoleId == roleId
                select up.AccessProfileId
            ).AnyAsync(ct);

            if (coveredByOtherProfile)
                continue; // otro perfil activo del usuario también otorga este rol

            var userRole = await _db.UserRoles
                .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId, ct);

            // Solo se revoca si el rol vino de ESTE perfil; si fue asignado directo o por
            // otro mecanismo, se deja intacto (no es competencia de este perfil quitarlo).
            if (userRole is not null && !userRole.IsDeleted && userRole.AssignedVia == source)
            {
                await _userRoles.DeleteAsync(userId, roleId);
            }
        }

        assignment.IsDeleted = true;
        await _userProfileRepo.UpdateAsync(assignment);
    }
}
