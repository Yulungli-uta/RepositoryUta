using System.Security.Claims;
using MapsterMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

/// <summary>
/// Servicio de asignación de roles con trazabilidad en RoleChangeHistory.
/// Reemplaza el CrudService genérico para UserRole.
/// </summary>
public class UserRoleService : ICrudService<UserRole, CreateUserRoleDto, UpdateUserRoleDto>
{
    private readonly IGenericRepository<UserRole> _userRoleRepo;
    private readonly IGenericRepository<RoleChangeHistory> _historyRepo;
    private readonly IMapper _map;
    private readonly IHttpContextAccessor _http;

    public UserRoleService(
        IGenericRepository<UserRole> userRoleRepo,
        IGenericRepository<RoleChangeHistory> historyRepo,
        IMapper map,
        IHttpContextAccessor http)
    {
        _userRoleRepo = userRoleRepo;
        _historyRepo  = historyRepo;
        _map          = map;
        _http         = http;
    }

    public Task<PagedResult<UserRole>> ListAsync(int page, int pageSize, CancellationToken ct = default) =>
        _userRoleRepo.GetPagedAsync(page, pageSize, ct);

    public Task<UserRole?> GetAsync(params object[] key) =>
        _userRoleRepo.GetAsync(key);

    /// <summary>
    /// Asigna un rol a un usuario. Si ya existe una asignación activa del mismo rol
    /// (no eliminada y no expirada), rechaza la operación con un mensaje claro en vez
    /// de insertar una fila duplicada. Si existe una asignación inactiva (removida o
    /// expirada) para el mismo usuario+rol, la reactiva en lugar de insertar una nueva,
    /// ya que (UserId, RoleId) es la clave primaria de la tabla.
    /// </summary>
    public async Task<UserRole> CreateAsync(CreateUserRoleDto dto)
    {
        var now = DateTime.Now;
        var existing = await _userRoleRepo.Query()
            .FirstOrDefaultAsync(x => x.UserId == dto.UserId && x.RoleId == dto.RoleId);

        if (existing is not null)
        {
            var isActive = !existing.IsDeleted && (existing.ExpiresAt is null || existing.ExpiresAt > now);
            if (isActive)
                throw new InvalidOperationException("El usuario ya tiene este rol asignado.");

            existing.IsDeleted   = false;
            existing.AssignedAt  = now;
            existing.ExpiresAt   = dto.ExpiresAt;
            existing.AssignedBy  = dto.AssignedBy ?? GetCurrentUserEmail();
            existing.Reason      = dto.Reason;
            existing.AssignedVia = dto.AssignedVia;
            var reactivated = await _userRoleRepo.UpdateAsync(existing);

            await _historyRepo.AddAsync(new RoleChangeHistory
            {
                UserId           = dto.UserId,
                RoleId           = dto.RoleId,
                ChangeType       = "Assigned",
                ChangedBy        = GetCurrentUserEmail(),
                ChangeReason     = dto.Reason,
                NewValue         = dto.RoleId.ToString(),
                EffectiveFrom    = now,
                EffectiveTo      = dto.ExpiresAt,
                ApprovalRequired = false,
            });

            return reactivated!;
        }

        var entity = _map.Map<UserRole>(dto);
        var result = await _userRoleRepo.AddAsync(entity);

        await _historyRepo.AddAsync(new RoleChangeHistory
        {
            UserId           = dto.UserId,
            RoleId           = dto.RoleId,
            ChangeType       = "Assigned",
            ChangedBy        = GetCurrentUserEmail(),
            ChangeReason     = dto.Reason,
            NewValue         = dto.RoleId.ToString(),
            EffectiveFrom    = now,
            EffectiveTo      = dto.ExpiresAt,
            ApprovalRequired = false,
        });

        return result;
    }

    public async Task<UserRole?> UpdateAsync(object key, UpdateUserRoleDto dto)
    {
        var keys = key as object[] ?? new[] { key };
        var current = await _userRoleRepo.GetAsync(keys);
        if (current is null) return null;
        _map.Map(dto, current);
        return await _userRoleRepo.UpdateAsync(current);
    }

    /// <summary>
    /// Remueve el rol de un usuario mediante soft-delete (IsDeleted=true), preservando
    /// la fila para que una futura reasignación del mismo rol la reactive en CreateAsync.
    /// </summary>
    public async Task<bool> DeleteAsync(params object[] key)
    {
        var existing = await _userRoleRepo.GetAsync(key);
        if (existing is null) return false;

        existing.IsDeleted = true;
        await _userRoleRepo.UpdateAsync(existing);

        await _historyRepo.AddAsync(new RoleChangeHistory
        {
            UserId           = existing.UserId,
            RoleId           = existing.RoleId,
            ChangeType       = "Revoked",
            ChangedBy        = GetCurrentUserEmail(),
            PreviousValue    = existing.RoleId.ToString(),
            EffectiveFrom    = DateTime.Now,
            ApprovalRequired = false,
        });

        return true;
    }

    private string GetCurrentUserEmail() =>
        _http.HttpContext?.User?.FindFirst(ClaimTypes.Email)?.Value
        ?? _http.HttpContext?.User?.FindFirst("email")?.Value
        ?? "system";
}
