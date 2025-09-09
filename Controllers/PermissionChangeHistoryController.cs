// Controllers/PermissionChangeHistoryController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/permission-change-history"), Authorize]
public class PermissionChangeHistoryController : ControllerBase
{
    private readonly ICrudService<PermissionChangeHistory, CreatePermissionChangeHistoryDto, UpdatePermissionChangeHistoryDto> _svc;
    public PermissionChangeHistoryController(ICrudService<PermissionChangeHistory, CreatePermissionChangeHistoryDto, UpdatePermissionChangeHistoryDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreatePermissionChangeHistoryDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpPut("{id:long}")]
    public async Task<IActionResult> Update(long id, [FromBody] UpdatePermissionChangeHistoryDto dto)
        => (await _svc.UpdateAsync(id, dto)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
}
