// Controllers/AccessProfilesController.cs
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Catálogo de perfiles de acceso (AccessProfile): agrupan uno o varios Roles bajo un
/// nombre reutilizable (ej. "Directora Administrativa"). No participan en la resolución
/// de menú ni de permisos — solo en la asignación masiva de roles a un usuario.
/// </summary>
[ApiController, Route("api/access-profiles"), Authorize(Roles = "Administrador,R_DITIC")]
public class AccessProfilesController : ControllerBase
{
    private readonly ICrudService<AccessProfile, CreateAccessProfileDto, UpdateAccessProfileDto> _svc;
    private readonly IGenericRepository<AccessProfile> _repo;
    private readonly IAuditService _audit;

    public AccessProfilesController(
        ICrudService<AccessProfile, CreateAccessProfileDto, UpdateAccessProfileDto> svc,
        IGenericRepository<AccessProfile> repo,
        IAuditService audit)
    {
        _svc = svc;
        _repo = repo;
        _audit = audit;
    }

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

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateAccessProfileDto dto)
    {
        var result = await _svc.CreateAsync(dto);
        await _audit.LogAsync(
            action: "AccessProfileCreated",
            module: "AccessProfiles",
            entityId: result.Id.ToString(),
            newValues: JsonSerializer.Serialize(new { result.Name, result.Description }));
        return Ok(ApiResponse.Ok(result));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateAccessProfileDto dto)
    {
        var updated = await _svc.UpdateAsync(id, dto);
        if (updated is null) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action: "AccessProfileUpdated",
            module: "AccessProfiles",
            entityId: id.ToString(),
            newValues: JsonSerializer.Serialize(new { dto.Description, dto.IsActive }));
        return Ok(ApiResponse.Ok(updated));
    }

    /// <summary>Soft-delete: marca el perfil como eliminado sin borrar la fila (preserva la trazabilidad de asignaciones históricas).</summary>
    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var entity = await _repo.GetAsync(id);
        if (entity is null) return NotFound(ApiResponse.Fail("No existe"));

        entity.IsDeleted = true;
        entity.IsActive = false;
        await _repo.UpdateAsync(entity);

        await _audit.LogAsync(action: "AccessProfileDeleted", module: "AccessProfiles", entityId: id.ToString());
        return Ok(ApiResponse.Ok(message: "Eliminado"));
    }
}
