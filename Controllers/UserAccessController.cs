using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

/// <summary>
/// Actividad de acceso de un usuario (inicios de sesión, renovaciones, cierres y anomalías) para
/// dar seguimiento a reportes del tipo "no puede entrar". Solo Administrador y R_DITIC.
/// </summary>
[ApiController, Route("api/user-access"), Authorize(Roles = "Administrador,R_DITIC")]
public class UserAccessController : ControllerBase
{
    private const int DefaultRangeDays = 7;

    private readonly IUserAccessService _svc;

    private readonly IAppClock _clock;

    public UserAccessController(IUserAccessService svc, IAppClock clock)
    {
        _svc = svc;
        _clock = clock;
    }

    /// <summary>Línea de tiempo del usuario, de la más reciente a la más antigua (rango máximo 31 días).</summary>
    [HttpGet("{userId:guid}/timeline")]
    public async Task<IActionResult> GetTimeline(
        Guid userId,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        CancellationToken ct = default)
    {
        var end = to ?? _clock.Now;
        var start = from ?? end.AddDays(-DefaultRangeDays);

        var result = await _svc.GetTimelineAsync(userId, start, end, page, pageSize, ct);
        return result is null
            ? NotFound(ApiResponse.Fail("Usuario no encontrado"))
            : Ok(ApiResponse.Ok(result));
    }
}
