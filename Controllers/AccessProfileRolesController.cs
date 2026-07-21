// Controllers/AccessProfileRolesController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>Composición de un AccessProfile: qué Roles agrupa.</summary>
[ApiController, Route("api/access-profile-roles"), Authorize(Roles = "Administrador,R_DITIC")]
public class AccessProfileRolesController : ControllerBase
{
    private readonly ICrudService<AccessProfileRole, CreateAccessProfileRoleDto, UpdateAccessProfileRoleDto> _svc;
    private readonly IGenericRepository<AccessProfileRole> _repo;

    public AccessProfileRolesController(
        ICrudService<AccessProfileRole, CreateAccessProfileRoleDto, UpdateAccessProfileRoleDto> svc,
        IGenericRepository<AccessProfileRole> repo)
    {
        _svc = svc;
        _repo = repo;
    }

    /// <summary>Retorna TODOS los roles que componen un perfil, sin límite de paginación.</summary>
    [HttpGet("profile/{accessProfileId:int}")]
    public async Task<IActionResult> GetByProfile(int accessProfileId, CancellationToken ct)
    {
        var items = await _repo.Query().Where(x => x.AccessProfileId == accessProfileId).ToListAsync(ct);
        return Ok(ApiResponse.Ok(items));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateAccessProfileRoleDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));

    [HttpDelete("{accessProfileId:int}/{roleId:int}")]
    public async Task<IActionResult> Delete(int accessProfileId, int roleId)
        => (await _svc.DeleteAsync(accessProfileId, roleId)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
