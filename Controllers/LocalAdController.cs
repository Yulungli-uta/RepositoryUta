using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController, Route("api/local-ad"), Authorize]
//[Authorize(Roles = "Administrador")]
public class LocalAdController : ControllerBase
{
    private readonly IIdentityProviderResolver _resolver;
    private readonly ILogger<LocalAdController> _logger;

    public LocalAdController(IIdentityProviderResolver resolver, ILogger<LocalAdController> logger)
    {
        _resolver = resolver;
        _logger = logger;
    }

    // ── Autenticación ─────────────────────────────────────────────────────────

    /// <summary>Autentica un usuario contra Active Directory local mediante LDAP bind.</summary>
    [HttpPost("authenticate")]
    [AllowAnonymous]
    public async Task<IActionResult> Authenticate([FromBody] LocalAdAuthRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return BadRequest(ApiResponse.Fail("Usuario y contraseña son requeridos"));

        var provider = _resolver.GetProvider("LocalAd");
        var result = await provider.AuthenticateAsync(
            new ProviderAuthRequest("LocalAd", req.Username, req.Password,
                HttpContext.Connection.RemoteIpAddress?.ToString(),
                Request.Headers.UserAgent));

        if (!result.Success)
            return Unauthorized(ApiResponse.Fail("Credenciales inválidas"));

        return Ok(ApiResponse.Ok(
            new LocalAdAuthResponse(true, result.Email, result.DisplayName),
            "Autenticación exitosa"));
    }

    // ── Usuarios ──────────────────────────────────────────────────────────────

    /// <summary>Lista usuarios del directorio con paginación y filtro opcional.</summary>
    [HttpGet("users")]
    public async Task<IActionResult> ListUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? filter = null,
        CancellationToken ct = default)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var users = await dir.ListUsersAsync(page, pageSize, filter, ct);
        var mapped = users.Select(MapUser).ToList();
        // LDAP no expone total count; se usa el conteo de la página actual como aproximación.
        return Ok(ApiResponse.Ok(PagedResult<LocalAdUserResponse>.Create(mapped, page, pageSize, mapped.Count)));
    }

    /// <summary>Obtiene un usuario por su objectGUID.</summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var user = await dir.GetUserAsync(id);
        return user is null
            ? NotFound(ApiResponse.Fail($"Usuario '{id}' no encontrado en AD"))
            : Ok(ApiResponse.Ok(MapUser(user)));
    }

    /// <summary>Obtiene un usuario por su dirección de email o userPrincipalName.</summary>
    [HttpGet("users/by-email/{email}")]
    public async Task<IActionResult> GetUserByEmail(string email)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var user = await dir.GetUserByEmailAsync(email);
        return user is null
            ? NotFound(ApiResponse.Fail($"Usuario '{email}' no encontrado en AD"))
            : Ok(ApiResponse.Ok(MapUser(user)));
    }

    /// <summary>Crea un nuevo usuario en AD local. Requiere LDAPS (puerto 636) para setear contraseña.</summary>
    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateLocalAdUserRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.DisplayName) || string.IsNullOrWhiteSpace(req.InitialPassword))
            return BadRequest(ApiResponse.Fail("Email, DisplayName e InitialPassword son requeridos"));

        var dir = _resolver.GetDirectory("LocalAd");
        var newUser = new DirectoryUser(
            string.Empty, req.Email, req.DisplayName,
            req.GivenName, req.Surname, req.JobTitle, req.Department, req.AccountEnabled, null);

        var created = await dir.CreateUserAsync(newUser, req.InitialPassword, req.ForcePasswordChange);
        _logger.LogInformation("Usuario AD local creado: {Email}", req.Email);
        return CreatedAtAction(nameof(GetUser), new { id = created.Id }, ApiResponse.Ok(MapUser(created), "Usuario creado en AD"));
    }

    /// <summary>Actualiza atributos de un usuario existente en AD local.</summary>
    [HttpPut("users/{id}")]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateLocalAdUserRequest req)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var existing = await dir.GetUserAsync(id);
        if (existing is null)
            return NotFound(ApiResponse.Fail($"Usuario '{id}' no encontrado en AD"));

        var updated = existing with
        {
            DisplayName = req.DisplayName ?? existing.DisplayName,
            GivenName = req.GivenName ?? existing.GivenName,
            Surname = req.Surname ?? existing.Surname,
            JobTitle = req.JobTitle ?? existing.JobTitle,
            Department = req.Department ?? existing.Department
        };

        var result = await dir.UpdateUserAsync(id, updated);
        return Ok(ApiResponse.Ok(MapUser(result), "Usuario actualizado"));
    }

    /// <summary>Habilita la cuenta de un usuario en AD local.</summary>
    [HttpPost("users/{id}/enable")]
    public async Task<IActionResult> EnableUser(string id)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        await dir.SetUserEnabledAsync(id, true);
        _logger.LogInformation("Usuario AD local habilitado: {Id}", id);
        return Ok(ApiResponse.Ok(null, "Usuario habilitado"));
    }

    /// <summary>Deshabilita la cuenta de un usuario en AD local.</summary>
    [HttpPost("users/{id}/disable")]
    public async Task<IActionResult> DisableUser(string id)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        await dir.SetUserEnabledAsync(id, false);
        _logger.LogInformation("Usuario AD local deshabilitado: {Id}", id);
        return Ok(ApiResponse.Ok(null, "Usuario deshabilitado"));
    }

    /// <summary>Elimina un usuario del directorio AD local.</summary>
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(string id)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var existing = await dir.GetUserAsync(id);
        if (existing is null)
            return NotFound(ApiResponse.Fail($"Usuario '{id}' no encontrado en AD"));

        await dir.DeleteUserAsync(id);
        _logger.LogInformation("Usuario AD local eliminado: {Id}", id);
        return Ok(ApiResponse.Ok(null, "Usuario eliminado del directorio"));
    }

    // ── Grupos ────────────────────────────────────────────────────────────────

    /// <summary>Lista grupos del directorio con paginación y filtro opcional.</summary>
    [HttpGet("groups")]
    public async Task<IActionResult> ListGroups(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? filter = null,
        CancellationToken ct = default)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var groups = await dir.ListGroupsAsync(page, pageSize, filter, ct);
        var mapped = groups.Select(MapGroup).ToList();
        return Ok(ApiResponse.Ok(PagedResult<LocalAdGroupResponse>.Create(mapped, page, pageSize, mapped.Count)));
    }

    /// <summary>Obtiene un grupo por su objectGUID.</summary>
    [HttpGet("groups/{id}")]
    public async Task<IActionResult> GetGroup(string id)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var group = await dir.GetGroupAsync(id);
        return group is null
            ? NotFound(ApiResponse.Fail($"Grupo '{id}' no encontrado en AD"))
            : Ok(ApiResponse.Ok(MapGroup(group)));
    }

    /// <summary>Agrega un usuario a un grupo de AD local.</summary>
    [HttpPost("groups/{groupId}/members/{userId}")]
    public async Task<IActionResult> AddUserToGroup(string groupId, string userId)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        await dir.AddUserToGroupAsync(groupId, userId);
        _logger.LogInformation("Usuario {UserId} agregado al grupo {GroupId} en AD local", userId, groupId);
        return Ok(ApiResponse.Ok(null, "Usuario agregado al grupo"));
    }

    /// <summary>Remueve un usuario de un grupo de AD local.</summary>
    [HttpDelete("groups/{groupId}/members/{userId}")]
    public async Task<IActionResult> RemoveUserFromGroup(string groupId, string userId)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        await dir.RemoveUserFromGroupAsync(groupId, userId);
        _logger.LogInformation("Usuario {UserId} removido del grupo {GroupId} en AD local", userId, groupId);
        return Ok(ApiResponse.Ok(null, "Usuario removido del grupo"));
    }

    /// <summary>Lista los miembros (usuarios) de un grupo de AD local.</summary>
    [HttpGet("groups/{groupId}/members")]
    public async Task<IActionResult> GetGroupMembers(string groupId)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var group = await dir.GetGroupAsync(groupId);
        if (group is null)
            return NotFound(ApiResponse.Fail($"Grupo '{groupId}' no encontrado en AD"));

        var members = await dir.GetUserGroupsAsync(groupId);
        return Ok(ApiResponse.Ok(members.Select(MapGroup)));
    }

    /// <summary>Lista los grupos a los que pertenece un usuario de AD local.</summary>
    [HttpGet("users/{userId}/groups")]
    public async Task<IActionResult> GetUserGroups(string userId)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var groups = await dir.GetUserGroupsAsync(userId);
        return Ok(ApiResponse.Ok(groups.Select(MapGroup), $"{groups.Count} grupo(s)"));
    }

    /// <summary>Verifica si un usuario pertenece a un grupo específico de AD local.</summary>
    [HttpGet("users/{userId}/groups/{groupId}")]
    public async Task<IActionResult> IsUserInGroup(string userId, string groupId)
    {
        var dir = _resolver.GetDirectory("LocalAd");
        var isMember = await dir.IsUserInGroupAsync(groupId, userId);
        return Ok(ApiResponse.Ok(new { isMember }, isMember ? "El usuario pertenece al grupo" : "El usuario no pertenece al grupo"));
    }

    // ── Mappers ───────────────────────────────────────────────────────────────

    private static LocalAdUserResponse MapUser(DirectoryUser u) =>
        new(u.Id, u.Email, u.DisplayName, u.GivenName, u.Surname, u.JobTitle, u.Department, u.AccountEnabled);

    private static LocalAdGroupResponse MapGroup(DirectoryGroup g) =>
        new(g.Id, g.Name, g.Description, g.Email);
}
