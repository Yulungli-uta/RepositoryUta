// Controllers/UserRolesController.cs
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/user-roles"), Authorize(Roles = "Administrador,R_DITIC")]
public class UserRolesController : ControllerBase
{
    private readonly ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> _svc;
    private readonly IAuditService _audit;

    public UserRolesController(ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto> svc, IAuditService audit)
    {
        _svc = svc;
        _audit = audit;
    }

    private string GetCurrentUserEmail() =>
        User.FindFirst(ClaimTypes.Email)?.Value
        ?? User.FindFirst("email")?.Value
        ?? "system";

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
    {
        var pagedEntities = await _svc.ListAsync(page, pageSize, ct);
        return Ok(new
        {
            items = pagedEntities.Items,
            page = pagedEntities.Page,
            pageSize = pagedEntities.PageSize,
            totalCount = pagedEntities.TotalCount,
            totalPages = pagedEntities.TotalPages,
            hasPreviousPage = pagedEntities.HasPreviousPage,
            hasNextPage = pagedEntities.HasNextPage
        });
    }
    [HttpGet("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Get(Guid userId, int roleId)
        => (await _svc.GetAsync(userId, roleId)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRoleDto dto)
    {
        try
        {
            var created = await _svc.CreateAsync(dto);

            await _audit.LogAsync(
                action: "RoleAssigned",
                module: "UserRoles",
                entityId: dto.RoleId.ToString(),
                newValues: $"UserId={dto.UserId}; ExpiresAt={dto.ExpiresAt}; Reason={dto.Reason}; AssignedBy={dto.AssignedBy ?? GetCurrentUserEmail()}",
                userId: dto.UserId);

            return Ok(ApiResponse.Ok(created));
        }
        catch (InvalidOperationException ex)
        {
            return Conflict(ApiResponse.Fail(ex.Message));
        }
    }

    [HttpPut("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Update(Guid userId, int roleId, [FromBody] UpdateUserRoleDto dto)
    {
        var updated = await _svc.UpdateAsync(new object[] { userId, roleId }, dto);
        if (updated is null) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action: "RoleAssignmentUpdated",
            module: "UserRoles",
            entityId: roleId.ToString(),
            newValues: $"UserId={userId}; ExpiresAt={dto.ExpiresAt}; Reason={dto.Reason}; UpdatedBy={GetCurrentUserEmail()}",
            userId: userId);

        return Ok(ApiResponse.Ok(updated));
    }

    [HttpDelete("{userId:guid}/{roleId:int}")]
    public async Task<IActionResult> Delete(Guid userId, int roleId)
    {
        var deleted = await _svc.DeleteAsync(userId, roleId);
        if (!deleted) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action: "RoleUnassigned",
            module: "UserRoles",
            entityId: roleId.ToString(),
            oldValues: $"UserId={userId}; RemovedBy={GetCurrentUserEmail()}",
            userId: userId);

        return Ok(ApiResponse.Ok(message: "Eliminado"));
    }
}
