using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/users"), Authorize]
public class UsersController : ControllerBase
{
    private const int DefaultPageSize = 20;
    private const int MaxPageSize = 200;

    private readonly ICrudService<User, CreateUserDto, UpdateUserDto> _svc;
    private readonly AuthDbContext _context;
    private readonly IUserPermissionService _permissionService;
    private readonly IUserRegistrationService _userRegistrationService;
    private readonly IAuditService _audit;

    public UsersController(
        ICrudService<User, CreateUserDto, UpdateUserDto> svc,
        AuthDbContext context,
        IUserPermissionService permissionService,
        IUserRegistrationService userRegistrationService,
        IAuditService audit)
    {
        _svc = svc;
        _context = context;
        _permissionService = permissionService;
        _userRegistrationService = userRegistrationService;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, pageSize, ct)));

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    //[HttpPost]
    //public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
    //    => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
    {
        try
        {
            var result = await _userRegistrationService.CreateUserWithEmployeeAsync(dto);

            await _audit.LogAsync(
                action:    "UserCreated",
                module:    "Users",
                newValues: JsonSerializer.Serialize(result));

            return Ok(ApiResponse.Ok(result));
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
        catch (Exception ex)
        {
            return StatusCode(500, ApiResponse.Fail($"Error interno: {ex.Message}"));
        }
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateUserDto dto)
    {
        var before = await _svc.GetAsync(id);
        if (before is null) return NotFound(ApiResponse.Fail("No existe"));

        var updated = await _svc.UpdateAsync(id, dto);
        if (updated is null) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action:    "UserUpdated",
            module:    "Users",
            entityId:  id.ToString(),
            oldValues: JsonSerializer.Serialize(new { before.Email, before.DisplayName, before.IsActive, before.UserType }),
            newValues: JsonSerializer.Serialize(new { updated.Email, updated.DisplayName, updated.IsActive, updated.UserType }));

        return Ok(ApiResponse.Ok(updated));
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var user = await _context.Users.FindAsync(id);
        if (user == null) return NotFound(ApiResponse.Fail("No existe"));

        // Snapshot para auditoría antes de eliminar
        var snapshot = JsonSerializer.Serialize(new { user.Email, user.DisplayName, user.UserType, user.IsActive });

        // Eliminar registros dependientes que tienen FK hacia tbl_Users
        // NOTA: RoleChangeHistory NO se elimina para preservar el historial de auditoría de roles
        _context.UserEmployees.RemoveRange(_context.UserEmployees.Where(x => x.UserId == id));
        _context.UserRoles.RemoveRange(_context.UserRoles.Where(x => x.UserId == id));
        _context.UserSessions.RemoveRange(_context.UserSessions.Where(x => x.UserId == id));
        _context.SecurityTokens.RemoveRange(_context.SecurityTokens.Where(x => x.UserId == id));
        _context.PasswordHistory.RemoveRange(_context.PasswordHistory.Where(x => x.UserId == id));
        _context.UserAccountLocks.RemoveRange(_context.UserAccountLocks.Where(x => x.UserId == id));
        _context.UserActivityLogs.RemoveRange(_context.UserActivityLogs.Where(x => x.UserId == id));
        _context.UserProvisionings.RemoveRange(_context.UserProvisionings.Where(x => x.AuthUserId == id));

        var localCred = await _context.LocalUserCredentials.FindAsync(id);
        if (localCred != null) _context.LocalUserCredentials.Remove(localCred);

        _context.Users.Remove(user);
        await _context.SaveChangesAsync();

        await _audit.LogAsync(
            action:    "UserDeleted",
            module:    "Users",
            entityId:  id.ToString(),
            oldValues: snapshot);

        return Ok(ApiResponse.Ok(message: "Eliminado"));
    }

    [HttpGet("{userId:guid}/permissions")]
    public async Task<IActionResult> GetUserPermissions(Guid userId)
    {
        try
        {
            var permissions = await _permissionService.GetUserPermissionsAsync(userId);
            return Ok(ApiResponse.Ok(permissions, "Permisos obtenidos exitosamente"));
        }
        catch (Exception ex)
        {
            return StatusCode(500, ApiResponse.Fail($"Error obteniendo permisos: {ex.Message}"));
        }
    }

    // ✅ Endpoint que tu frontend está llamando: /api/users/paged
    [HttpGet("paged")]
    public async Task<IActionResult> GetPaged(
        [FromQuery] PagedRequestDto req,
        [FromQuery] bool? isActive,
        [FromQuery] string? userType,
        CancellationToken ct)
    {
        req.Normalize(MaxPageSize);

        // Orden predeterminado: último login descendente
        var sortBy = (req.SortBy ?? "lastlogin").ToLowerInvariant();
        var desc   = sortBy == "lastlogin" ? req.SortDirection != "asc" : req.SortDirection == "desc";
        var search = req.Search;

        IQueryable<User> q = _context.Users.AsNoTracking();

        // Filtro por texto (email o nombre)
        if (!string.IsNullOrWhiteSpace(search))
            q = q.Where(u =>
                (u.Email        != null && u.Email.Contains(search)) ||
                (u.DisplayName  != null && u.DisplayName.Contains(search)));

        // Filtro por estado
        if (isActive.HasValue)
            q = q.Where(u => u.IsActive == isActive.Value);

        // Filtro por tipo de usuario
        if (!string.IsNullOrWhiteSpace(userType))
            q = q.Where(u => u.UserType == userType);

        q = ApplyUserSorting(q, sortBy, desc);

        var totalCount = await q.LongCountAsync(ct);
        var items = await q
            .Skip((req.Page - 1) * req.PageSize)
            .Take(req.PageSize)
            .ToListAsync(ct);

        return Ok(ApiResponse.Ok(PagedResult<User>.Create(items, req.Page, req.PageSize, totalCount)));
    }

    private static IQueryable<User> ApplyUserSorting(IQueryable<User> q, string sortBy, bool desc)
    {
        return sortBy switch
        {
            "email"       => desc ? q.OrderByDescending(u => u.Email)       : q.OrderBy(u => u.Email),
            "displayname" => desc ? q.OrderByDescending(u => u.DisplayName)  : q.OrderBy(u => u.DisplayName),
            "usertype"    => desc ? q.OrderByDescending(u => u.UserType)     : q.OrderBy(u => u.UserType),
            "isactive"    => desc ? q.OrderByDescending(u => u.IsActive)     : q.OrderBy(u => u.IsActive),
            "lastlogin"   => desc ? q.OrderByDescending(u => u.LastLogin)    : q.OrderBy(u => u.LastLogin),
            _             => q.OrderByDescending(u => u.LastLogin),
        };
    }
}