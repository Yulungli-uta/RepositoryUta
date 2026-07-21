// Controllers/UserAccessProfilesController.cs
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Asignación de AccessProfiles a usuarios. Asignar un perfil expande sus roles a filas
/// concretas de UserRole (ver IAccessProfileAssignmentService); quitar un perfil solo
/// revoca los roles que ese perfil otorgó y que ningún otro perfil/asignación directa
/// sigue necesitando.
/// </summary>
[ApiController, Route("api/user-access-profiles"), Authorize(Roles = "Administrador,R_DITIC")]
public class UserAccessProfilesController : ControllerBase
{
    private readonly IAccessProfileAssignmentService _assignment;
    private readonly IAuditService _audit;

    public UserAccessProfilesController(IAccessProfileAssignmentService assignment, IAuditService audit)
    {
        _assignment = assignment;
        _audit = audit;
    }

    /// <summary>Perfiles (activos) asignados actualmente a un usuario — solo informativo, no autoriza nada por sí mismo.</summary>
    [HttpGet("user/{userId:guid}")]
    public async Task<IActionResult> GetByUser(Guid userId, CancellationToken ct)
    {
        var profiles = await _assignment.GetAssignedProfilesAsync(userId, ct);
        return Ok(ApiResponse.Ok(profiles));
    }

    [HttpPost]
    public async Task<IActionResult> Assign([FromBody] AssignAccessProfileDto dto, CancellationToken ct)
    {
        var assignedBy = dto.AssignedBy ?? GetCurrentUserEmail();
        await _assignment.AssignAsync(dto.UserId, dto.AccessProfileId, assignedBy, ct);

        await _audit.LogAsync(
            action: "AccessProfileAssigned",
            module: "UserAccessProfiles",
            entityId: dto.AccessProfileId.ToString(),
            newValues: $"UserId={dto.UserId}; AssignedBy={assignedBy}",
            userId: dto.UserId);

        return Ok(ApiResponse.Ok(message: "Perfil asignado."));
    }

    [HttpDelete("{userId:guid}/{accessProfileId:int}")]
    public async Task<IActionResult> Unassign(Guid userId, int accessProfileId, CancellationToken ct)
    {
        var removedBy = GetCurrentUserEmail();
        await _assignment.UnassignAsync(userId, accessProfileId, removedBy, ct);

        await _audit.LogAsync(
            action: "AccessProfileUnassigned",
            module: "UserAccessProfiles",
            entityId: accessProfileId.ToString(),
            oldValues: $"UserId={userId}; RemovedBy={removedBy}",
            userId: userId);

        return Ok(ApiResponse.Ok(message: "Perfil removido."));
    }

    private string GetCurrentUserEmail() =>
        User.FindFirst(ClaimTypes.Email)?.Value
        ?? User.FindFirst("email")?.Value
        ?? "system";
}
