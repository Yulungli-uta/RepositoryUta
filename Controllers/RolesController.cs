using System.Linq.Expressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/roles")]
[Authorize(Roles = "Administrador,R_DITIC")]
public class RolesController : ControllerBase
{
    private readonly ICrudService<Role, CreateRoleDto, UpdateRoleDto> _svc;
    private readonly IAuditService _audit;

    public RolesController(ICrudService<Role, CreateRoleDto, UpdateRoleDto> svc, IAuditService audit)
    {
        _svc   = svc;
        _audit = audit;
    }

    [AllowAnonymous]
    [HttpGet("ping")]
    public IActionResult Ping()
    {
        return Ok("roles controller activo");
    }

    /// <summary>
    /// Lista roles paginados. Con <c>search</c> filtra en el servidor por nombre o descripción: cada palabra escrita
    /// debe aparecer en alguno de los dos (sin distinguir mayúsculas según la collation) y se ordena por nombre.
    /// Sin <c>search</c> el comportamiento es el de siempre.
    /// </summary>
    [HttpGet]
    public async Task<IActionResult> List(
        [FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] string? search = null, CancellationToken ct = default)
    {
        var predicate = BuildSearchPredicate(search);
        var result = predicate is null
            ? await _svc.ListAsync(page, pageSize, ct)
            : await _svc.ListAsync(predicate, page, pageSize, ct, orderBy: r => r.Name);
        return Ok(ApiResponse.Ok(result));
    }

    private static Expression<Func<Role, bool>>? BuildSearchPredicate(string? search)
    {
        var terms = (search ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (terms.Length == 0) return null;

        var parameter = Expression.Parameter(typeof(Role), "r");
        Expression? body = null;
        foreach (var raw in terms)
        {
            var term = raw;
            Expression<Func<Role, bool>> one = r => r.Name.Contains(term) || (r.Description != null && r.Description.Contains(term));
            var replaced = new ReplaceParameterVisitor(one.Parameters[0], parameter).Visit(one.Body);
            body = body is null ? replaced : Expression.AndAlso(body, replaced);
        }
        return Expression.Lambda<Func<Role, bool>>(body!, parameter);
    }

    private sealed class ReplaceParameterVisitor(ParameterExpression from, ParameterExpression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) => node == from ? to : base.VisitParameter(node);
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var entity = await _svc.GetAsync(id);
        return entity is not null
            ? Ok(ApiResponse.Ok(entity))
            : NotFound(ApiResponse.Fail("No existe"));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateRoleDto dto)
    {
        var result = await _svc.CreateAsync(dto);

        await _audit.LogAsync(
            action:    "RoleCreated",
            module:    "Roles",
            entityId:  result.Id.ToString(),
            newValues: JsonSerializer.Serialize(new { result.Name, result.Description, result.Priority }));

        return Ok(ApiResponse.Ok(result));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateRoleDto dto)
    {
        var before = await _svc.GetAsync(id);
        if (before is null) return NotFound(ApiResponse.Fail("No existe"));

        var updated = await _svc.UpdateAsync(id, dto);
        if (updated is null) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action:    "RoleUpdated",
            module:    "Roles",
            entityId:  id.ToString(),
            oldValues: JsonSerializer.Serialize(new { before.Name, before.Description, before.Priority, before.IsActive }),
            newValues: JsonSerializer.Serialize(new { updated.Name, updated.Description, updated.Priority, updated.IsActive }));

        return Ok(ApiResponse.Ok(updated));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var before = await _svc.GetAsync(id);
        if (before is null) return NotFound(ApiResponse.Fail("No existe"));

        var deleted = await _svc.DeleteAsync(id);
        if (!deleted) return NotFound(ApiResponse.Fail("No existe"));

        await _audit.LogAsync(
            action:    "RoleDeleted",
            module:    "Roles",
            entityId:  id.ToString(),
            oldValues: JsonSerializer.Serialize(new { before.Name, before.Description, before.IsActive }));

        return Ok(ApiResponse.Ok(message: "Eliminado"));
    }
}