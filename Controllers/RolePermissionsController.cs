// Controllers/RolePermissionsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/role-permissions"), Authorize(Roles = "Administrador,R_DITIC")]
public class RolePermissionsController : ControllerBase
{
    private readonly ICrudService<RolePermission, CreateRolePermissionDto, UpdateRolePermissionDto> _svc;
    private readonly IGenericRepository<RolePermission> _repo;
    private readonly AuthDbContext _db;

    public RolePermissionsController(
        ICrudService<RolePermission, CreateRolePermissionDto, UpdateRolePermissionDto> svc,
        IGenericRepository<RolePermission> repo,
        AuthDbContext db)
    {
        _svc = svc;
        _repo = repo;
        _db = db;
    }

    /// <summary>
    /// Permisos de acción efectivos (código "MODULO.ACCION") para la unión de un conjunto de
    /// roles. Público por diseño — es metadata de esquema RBAC (qué puede hacer un rol), no
    /// datos de un usuario ni de una sesión; mismo criterio que <c>/.well-known/jwks.json</c>.
    /// Consumido por servicios (ej. HrBackend) para resolver autorización de acción sin
    /// necesitar un flujo de autenticación servicio-a-servicio para esta consulta puntual.
    /// </summary>
    [HttpGet("effective")]
    [AllowAnonymous]
    [ResponseCache(Duration = 60)]
    public async Task<IActionResult> GetEffectivePermissions([FromQuery] string[] roles, CancellationToken ct)
    {
        if (roles is null || roles.Length == 0)
            return Ok(ApiResponse.Ok(Array.Empty<string>()));

        var codes = await (
            from ur in _db.Roles
            where roles.Contains(ur.Name) && ur.IsActive && !ur.IsDeleted
            join rp in _db.RolePermissions on ur.Id equals rp.RoleId
            join p in _db.Permissions on rp.PermissionId equals p.Id
            where !p.IsDeleted
            select (p.Module + "." + p.Action).ToUpper()
        ).Distinct().ToListAsync(ct);

        return Ok(ApiResponse.Ok(codes));
    }

    /// <summary>Retorna TODOS los permisos de acción asignados a un rol, sin límite de paginación.</summary>
    [HttpGet("role/{roleId:int}")]
    public async Task<IActionResult> GetByRole(int roleId, CancellationToken ct)
    {
        var items = await _repo.Query().Where(x => x.RoleId == roleId).ToListAsync(ct);
        return Ok(ApiResponse.Ok(items));
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

    [HttpGet("{roleId:int}/{permissionId:int}")]
    public async Task<IActionResult> Get(int roleId, int permissionId)
        => (await _svc.GetAsync(roleId, permissionId)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRolePermissionDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));

    [HttpDelete("{roleId:int}/{permissionId:int}")]
    public async Task<IActionResult> Delete(int roleId, int permissionId)
        => (await _svc.DeleteAsync(roleId, permissionId)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
