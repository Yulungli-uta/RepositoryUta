using System.Security.Claims;
using AutoMapper;
using Microsoft.AspNetCore.Http;
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

    public async Task<UserRole> CreateAsync(CreateUserRoleDto dto)
    {
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
            EffectiveFrom    = DateTime.UtcNow,
            EffectiveTo      = dto.ExpiresAt,
            ApprovalRequired = false,
        });

        return result;
    }

    public async Task<UserRole?> UpdateAsync(object key, UpdateUserRoleDto dto)
    {
        var current = await _userRoleRepo.GetAsync(key);
        if (current is null) return null;
        _map.Map(dto, current);
        return await _userRoleRepo.UpdateAsync(current);
    }

    public async Task<bool> DeleteAsync(params object[] key)
    {
        var existing = await _userRoleRepo.GetAsync(key);
        var deleted  = await _userRoleRepo.DeleteAsync(key);

        if (deleted && existing is not null)
        {
            await _historyRepo.AddAsync(new RoleChangeHistory
            {
                UserId           = existing.UserId,
                RoleId           = existing.RoleId,
                ChangeType       = "Removed",
                ChangedBy        = GetCurrentUserEmail(),
                PreviousValue    = existing.RoleId.ToString(),
                EffectiveFrom    = DateTime.UtcNow,
                ApprovalRequired = false,
            });
        }

        return deleted;
    }

    private string GetCurrentUserEmail() =>
        _http.HttpContext?.User?.FindFirst(ClaimTypes.Email)?.Value
        ?? _http.HttpContext?.User?.FindFirst("email")?.Value
        ?? "system";
}
