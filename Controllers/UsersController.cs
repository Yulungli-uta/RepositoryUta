using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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

    public UsersController(
        ICrudService<User, CreateUserDto, UpdateUserDto> svc,
        AuthDbContext context,
        IUserPermissionService permissionService,
        IUserRegistrationService userRegistrationService)
    {
        _svc = svc;
        _context = context;
        _permissionService = permissionService;
        _userRegistrationService = userRegistrationService;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));

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
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));

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
    public async Task<IActionResult> GetPaged([FromQuery] PagedRequestDto req)
    {
        // Normalizar
        var page = req.Page < 1 ? 1 : req.Page;
        var pageSize = req.PageSize < 1 ? DefaultPageSize : req.PageSize;
        if (pageSize > MaxPageSize) pageSize = MaxPageSize;

        var sortBy = (req.SortBy ?? "email").Trim().ToLowerInvariant();
        var sortDir = (req.SortDirection ?? "asc").Trim().ToLowerInvariant();
        var desc = sortDir == "desc";

        var search = req.Search?.Trim();

        IQueryable<User> q = _context.Users.AsNoTracking();

        // Filtro de búsqueda
        if (!string.IsNullOrWhiteSpace(search))
        {
            // Opción simple (depende de collation DB)
            q = q.Where(u =>
                (u.Email != null && u.Email.Contains(search)) ||
                (u.DisplayName != null && u.DisplayName.Contains(search))
            );

            // Si quieres LIKE:
            // var pattern = $"%{search}%";
            // q = q.Where(u =>
            //     (u.Email != null && EF.Functions.Like(u.Email, pattern)) ||
            //     (u.DisplayName != null && EF.Functions.Like(u.DisplayName, pattern))
            // );
        }

        // Sorting lista blanca
        q = ApplyUserSorting(q, sortBy, desc);

        var totalCount = await q.CountAsync();
        var totalPages = totalCount == 0 ? 0 : (int)Math.Ceiling(totalCount / (double)pageSize);

        if (totalPages > 0 && page > totalPages) page = totalPages;

        var items = await q
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        var result = new PagedResult<User>
        {
            Items = items,
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount, 
            TotalPages = totalPages,
            HasPreviousPage = page > 1,
            HasNextPage = totalPages > 0 && page < totalPages
        };

        return Ok(ApiResponse.Ok(result));
    }

    private static IQueryable<User> ApplyUserSorting(IQueryable<User> q, string sortBy, bool desc)
    {
        return sortBy switch
        {
            "email" => desc ? q.OrderByDescending(u => u.Email) : q.OrderBy(u => u.Email),
            "displayname" => desc ? q.OrderByDescending(u => u.DisplayName) : q.OrderBy(u => u.DisplayName),
            "usertype" => desc ? q.OrderByDescending(u => u.UserType) : q.OrderBy(u => u.UserType),
            "isactive" => desc ? q.OrderByDescending(u => u.IsActive) : q.OrderBy(u => u.IsActive),
            "lastlogin" => desc ? q.OrderByDescending(u => u.LastLogin) : q.OrderBy(u => u.LastLogin),
            _ => desc ? q.OrderByDescending(u => u.Email) : q.OrderBy(u => u.Email),
        };
    }
}