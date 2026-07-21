// Controllers/AuditLogController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/audit-log"), Authorize(Roles = "Administrador,R_DITIC")]
public class AuditLogController : ControllerBase
{
    private readonly ICrudService<AuditLog, CreateAuditLogDto, UpdateAuditLogDto> _svc;
    private readonly IGenericRepository<AuditLog> _repo;

    public AuditLogController(ICrudService<AuditLog, CreateAuditLogDto, UpdateAuditLogDto> svc, IGenericRepository<AuditLog> repo)
    {
        _svc = svc;
        _repo = repo;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));

    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    /// <summary>
    /// Historial de auditoría filtrado por módulo (ej. "UserAccessProfiles", "UserRoles"),
    /// y opcionalmente por EntityId (ej. el Id del AccessProfile o RoleId) y/o UserId
    /// (el usuario afectado por el evento, no quien lo ejecutó). Más reciente primero,
    /// capado a `limit` filas (máx. 500) — no hay paginación real porque el volumen
    /// esperado para un módulo específico es bajo.
    /// </summary>
    [HttpGet("by-module/{module}")]
    public async Task<IActionResult> GetByModule(
        string module,
        [FromQuery] string? entityId,
        [FromQuery] Guid? userId,
        [FromQuery] int limit = 100,
        CancellationToken ct = default)
    {
        limit = Math.Clamp(limit, 1, 500);

        var query = _repo.Query().Where(a => a.Module == module);
        if (!string.IsNullOrWhiteSpace(entityId))
            query = query.Where(a => a.EntityId == entityId);
        if (userId.HasValue)
            query = query.Where(a => a.UserId == userId.Value);

        var items = await query
            .OrderByDescending(a => a.Timestamp)
            .Take(limit)
            .ToListAsync(ct);

        return Ok(ApiResponse.Ok(items));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateAuditLogDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));

    // Sin PUT/DELETE: el log de auditoría es append-only por diseño (no se edita ni se borra).
}
