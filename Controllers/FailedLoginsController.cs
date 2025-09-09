// Controllers/FailedLoginsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/failed-logins"), Authorize]
public class FailedLoginsController : ControllerBase
{
    private readonly ICrudService<FailedLoginAttempt, CreateFailedAttemptDto, UpdateFailedAttemptDto> _svc;
    public FailedLoginsController(ICrudService<FailedLoginAttempt, CreateFailedAttemptDto, UpdateFailedAttemptDto> svc) => _svc = svc;

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int size = 100)
        => Ok(ApiResponse.Ok(await _svc.ListAsync(page, size)));
    [HttpGet("{id:long}")]
    public async Task<IActionResult> Get(long id)
        => (await _svc.GetAsync(id)) is { } e ? Ok(ApiResponse.Ok(e)) : NotFound(ApiResponse.Fail("No existe"));
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateFailedAttemptDto dto)
        => Ok(ApiResponse.Ok(await _svc.CreateAsync(dto)));
    [HttpDelete("{id:long}")]
    public async Task<IActionResult> Delete(long id)
        => (await _svc.DeleteAsync(id)) ? Ok(ApiResponse.Ok(message: "Eliminado")) : NotFound(ApiResponse.Fail("No existe"));
}
