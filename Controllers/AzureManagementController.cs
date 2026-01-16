using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Graph.Models;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/azure-management")]
[Authorize(Roles = "Administrador")] // Solo administradores pueden gestionar Azure AD
public class AzureManagementController : ControllerBase
{
    private readonly IAzureManagementService _azureMgmt;
    private readonly ILogger<AzureManagementController> _logger;

    public AzureManagementController(
        IAzureManagementService azureMgmt,
        ILogger<AzureManagementController> logger)
    {
        _azureMgmt = azureMgmt;
        _logger = logger;
    }

    // ========== GESTIÓN DE USUARIOS ==========

    /// <summary>
    /// Crear un nuevo usuario en Azure AD
    /// </summary>
    [HttpPost("users")]
    public async Task<IActionResult> CreateUser([FromBody] CreateAzureUserDto dto)
    {
        try
        {
            var user = await _azureMgmt.CreateUserInAzureAsync(dto);
            return Ok(ApiResponse.Ok(user, "Usuario creado exitosamente en Azure AD"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error creating Azure user: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Obtener un usuario de Azure AD por ID
    /// </summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _azureMgmt.GetUserFromAzureAsync(id);
        return user != null
            ? Ok(ApiResponse.Ok(user))
            : NotFound(ApiResponse.Fail("Usuario no encontrado en Azure AD"));
    }

    /// <summary>
    /// Obtener un usuario de Azure AD por email
    /// </summary>
    [HttpGet("users/by-email/{email}")]
    public async Task<IActionResult> GetUserByEmail(string email)
    {
        var user = await _azureMgmt.GetUserByEmailFromAzureAsync(email);
        return user != null
            ? Ok(ApiResponse.Ok(user))
            : NotFound(ApiResponse.Fail("Usuario no encontrado en Azure AD"));
    }

    /// <summary>
    /// Actualizar un usuario en Azure AD
    /// </summary>
    [HttpPut("users/{id}")]
    public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateAzureUserDto dto)
    {
        try
        {
            var user = await _azureMgmt.UpdateUserInAzureAsync(id, dto);
            return user != null
                ? Ok(ApiResponse.Ok(user, "Usuario actualizado exitosamente"))
                : NotFound(ApiResponse.Fail("Usuario no encontrado"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error updating Azure user: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Habilitar un usuario en Azure AD
    /// </summary>
    [HttpPost("users/{id}/enable")]
    public async Task<IActionResult> EnableUser(string id)
    {
        var success = await _azureMgmt.EnableDisableUserInAzureAsync(id, true);
        return success
            ? Ok(ApiResponse.Ok(null, "Usuario habilitado exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al habilitar usuario"));
    }

    /// <summary>
    /// Deshabilitar un usuario en Azure AD
    /// </summary>
    [HttpPost("users/{id}/disable")]
    public async Task<IActionResult> DisableUser(string id)
    {
        var success = await _azureMgmt.EnableDisableUserInAzureAsync(id, false);
        return success
            ? Ok(ApiResponse.Ok(null, "Usuario deshabilitado exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al deshabilitar usuario"));
    }

    /// <summary>
    /// Eliminar un usuario de Azure AD
    /// </summary>
    [HttpDelete("users/{id}")]
    public async Task<IActionResult> DeleteUser(string id, [FromQuery] bool permanent = false)
    {
        var success = await _azureMgmt.DeleteUserFromAzureAsync(id, permanent);
        return success
            ? Ok(ApiResponse.Ok(null, "Usuario eliminado exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al eliminar usuario"));
    }

    /// <summary>
    /// Listar usuarios de Azure AD con paginación
    /// </summary>
    [HttpGet("users")]
    public async Task<IActionResult> ListUsers(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? filter = null)
    {
        _logger.LogInformation($"*************************Listing users: page={page}, pageSize={pageSize}, filter={filter}");
        var result = await _azureMgmt.ListUsersFromAzureAsync(page, pageSize, filter);
        string jsonResult = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        _logger.LogInformation("Resultado de Azure:\n{Data}", jsonResult);
        return Ok(ApiResponse.Ok(result));
    }

    // ========== GESTIÓN DE CONTRASEÑAS ==========
    
    /// <summary>
    /// Resetear contraseña de un usuario en Azure AD
    /// </summary>
    [HttpPost("users/{id}/reset-password")]
    public async Task<IActionResult> ResetPassword(string id, [FromQuery] bool forceChange = true)
    {
        try
        {
            var tempPassword = await _azureMgmt.ResetPasswordInAzureAsync(id, forceChange);
            return Ok(ApiResponse.Ok(new
            {
                TemporaryPassword = tempPassword,
                ForceChangeNextSignIn = forceChange,
                Message = "Contraseña reseteada exitosamente"
            }));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error resetting password: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Cambiar contraseña de un usuario en Azure AD
    /// </summary>
    [HttpPost("users/{id}/change-password")]
    public async Task<IActionResult> ChangePassword(string id, [FromBody] ChangePasswordDto dto)
    {
        try
        {
            var success = await _azureMgmt.ChangePasswordInAzureAsync(id, dto.NewPassword, dto.ForceChangeNextSignIn);
            return success
                ? Ok(ApiResponse.Ok(null, "Contraseña cambiada exitosamente"))
                : BadRequest(ApiResponse.Fail("Error al cambiar contraseña"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error changing password: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Validar si una contraseña cumple con la política
    /// </summary>
    [HttpPost("validate-password")]
    public async Task<IActionResult> ValidatePassword([FromBody] string password)
    {
        var result = await _azureMgmt.ValidatePasswordPolicyAsync(password);
        return Ok(ApiResponse.Ok(result));
    }

    /// <summary>
    /// Generar una contraseña segura
    /// </summary>
    [HttpGet("generate-password")]
    public async Task<IActionResult> GeneratePassword()
    {
        var password = await _azureMgmt.GenerateSecurePasswordAsync();
        return Ok(ApiResponse.Ok(new { Password = password }));
    }

    // ========== GESTIÓN DE ROLES DE AZURE AD ==========

    /// <summary>
    /// Listar todos los roles de directorio de Azure AD
    /// </summary>
    [HttpGet("azure-roles")]
    public async Task<IActionResult> GetAllAzureRoles()
    {
        var roles = await _azureMgmt.GetAllAzureDirectoryRolesAsync();
        return Ok(ApiResponse.Ok(roles));
    }

    /// <summary>
    /// Obtener roles de Azure AD de un usuario
    /// </summary>
    [HttpGet("users/{id}/azure-roles")]
    public async Task<IActionResult> GetUserAzureRoles(string id)
    {
        _logger.LogInformation($"*************************Listing AzureAD roles -GetUserAzureRoles : userid={id}");
        var roles = await _azureMgmt.GetUserAzureRolesAsync(id);

        // Serializar a JSON con formato legible
        var rolesJson = System.Text.Json.JsonSerializer.Serialize(
            roles,
            new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            });

        _logger.LogInformation($"AzureAD Roles response JSON: {rolesJson}");
        
        _logger.LogInformation($"*************************Listing AzureAD user -GetUserFromAzureAsync : userid={id}");
        var user = await _azureMgmt.GetUserFromAzureAsync(id);

        
        var userJson = System.Text.Json.JsonSerializer.Serialize(
           user,
           new System.Text.Json.JsonSerializerOptions
           {
               WriteIndented = true
           });
        _logger.LogInformation($"AzureAD user response JSON: {userJson}");
        _logger.LogInformation($"*************************Listing AzureAD user -GetUserAzureGroupsAsync : userid={id}");
        var userGroups = await _azureMgmt.GetUserAzureGroupsAsync(id);
        var userGroupsJson = System.Text.Json.JsonSerializer.Serialize(
           userGroups,
           new System.Text.Json.JsonSerializerOptions
           {
               WriteIndented = true
           });
        _logger.LogInformation($"AzureAD group response JSON: {userGroupsJson}");

        //_logger.LogInformation($"*************************Listing AzureAD user -allJson : userid={id}");
        //var alluserJson = await _azureMgmt.GetAllAzureDirectoryRolesAsync();

        //var allJson = System.Text.Json.JsonSerializer.Serialize(
        //   alluserJson,
        //   new System.Text.Json.JsonSerializerOptions
        //   {
        //       WriteIndented = true
        //   });

        //_logger.LogInformation($"AzureAD all response JSON: {allJson}");


        return Ok(ApiResponse.Ok(roles));
    }

    /// <summary>
    /// Asignar un rol de Azure AD a un usuario
    /// </summary>
    [HttpPost("users/{userId}/azure-roles/{roleId}")]
    public async Task<IActionResult> AssignAzureRole(string userId, string roleId)
    {
        var success = await _azureMgmt.AssignAzureRoleAsync(userId, roleId);
        return success
            ? Ok(ApiResponse.Ok(null, "Rol de Azure AD asignado exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al asignar rol"));
    }

    /// <summary>
    /// Remover un rol de Azure AD de un usuario
    /// </summary>
    [HttpDelete("users/{userId}/azure-roles/{roleId}")]
    public async Task<IActionResult> RemoveAzureRole(string userId, string roleId)
    {
        var success = await _azureMgmt.RemoveAzureRoleAsync(userId, roleId);
        return success
            ? Ok(ApiResponse.Ok(null, "Rol de Azure AD removido exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al remover rol"));
    }

    /// <summary>
    /// Obtener miembros de un rol de Azure AD
    /// </summary>
    [HttpGet("azure-roles/{roleId}/members")]
    public async Task<IActionResult> GetRoleMembers(string roleId)
    {
        var members = await _azureMgmt.GetRoleMembersAsync(roleId);
        return Ok(ApiResponse.Ok(members));
    }

    // ========== GESTIÓN DE GRUPOS DE AZURE AD ==========

    /// <summary>
    /// Crear un grupo en Azure AD
    /// </summary>
    [HttpPost("groups")]
    public async Task<IActionResult> CreateGroup([FromBody] CreateAzureGroupDto dto)
    {
        try
        {
            var group = await _azureMgmt.CreateGroupInAzureAsync(dto);
            return Ok(ApiResponse.Ok(group, "Grupo creado exitosamente en Azure AD"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error creating Azure group: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Obtener un grupo de Azure AD por ID
    /// </summary>
    [HttpGet("groups/{id}")]
    public async Task<IActionResult> GetGroup(string id)
    {
        var group = await _azureMgmt.GetGroupFromAzureAsync(id);
        return group != null
            ? Ok(ApiResponse.Ok(group))
            : NotFound(ApiResponse.Fail("Grupo no encontrado en Azure AD"));
    }

    /// <summary>
    /// Actualizar un grupo en Azure AD
    /// </summary>
    [HttpPut("groups/{id}")]
    public async Task<IActionResult> UpdateGroup(string id, [FromBody] UpdateAzureGroupDto dto)
    {
        var group = await _azureMgmt.UpdateGroupInAzureAsync(id, dto);
        return group != null
            ? Ok(ApiResponse.Ok(group, "Grupo actualizado exitosamente"))
            : NotFound(ApiResponse.Fail("Grupo no encontrado"));
    }

    /// <summary>
    /// Eliminar un grupo de Azure AD
    /// </summary>
    [HttpDelete("groups/{id}")]
    public async Task<IActionResult> DeleteGroup(string id)
    {
        var success = await _azureMgmt.DeleteGroupFromAzureAsync(id);
        return success
            ? Ok(ApiResponse.Ok(null, "Grupo eliminado exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al eliminar grupo"));
    }

    /// <summary>
    /// Listar grupos de Azure AD con paginación
    /// </summary>
    [HttpGet("groups")]
    public async Task<IActionResult> ListGroups(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] string? filter = null)
    {
        var result = await _azureMgmt.ListGroupsFromAzureAsync(page, pageSize, filter);
        return Ok(ApiResponse.Ok(result));
    }

    /// <summary>
    /// Agregar un usuario a un grupo de Azure AD
    /// </summary>
    [HttpPost("groups/{groupId}/members/{userId}")]
    public async Task<IActionResult> AddUserToGroup(string groupId, string userId)
    {
        var success = await _azureMgmt.AddUserToAzureGroupAsync(groupId, userId);
        return success
            ? Ok(ApiResponse.Ok(null, "Usuario agregado al grupo exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al agregar usuario al grupo"));
    }

    /// <summary>
    /// Remover un usuario de un grupo de Azure AD
    /// </summary>
    [HttpDelete("groups/{groupId}/members/{userId}")]
    public async Task<IActionResult> RemoveUserFromGroup(string groupId, string userId)
    {
        var success = await _azureMgmt.RemoveUserFromAzureGroupAsync(groupId, userId);
        return success
            ? Ok(ApiResponse.Ok(null, "Usuario removido del grupo exitosamente"))
            : BadRequest(ApiResponse.Fail("Error al remover usuario del grupo"));
    }

    /// <summary>
    /// Obtener miembros de un grupo de Azure AD
    /// </summary>
    [HttpGet("groups/{groupId}/members")]
    public async Task<IActionResult> GetGroupMembers(string groupId)
    {
        var members = await _azureMgmt.GetGroupMembersAsync(groupId);
        return Ok(ApiResponse.Ok(members));
    }

    /// <summary>
    /// Obtener grupos de Azure AD de un usuario
    /// </summary>
    [HttpGet("users/{id}/azure-groups")]
    public async Task<IActionResult> GetUserAzureGroups(string id)
    {
        var groups = await _azureMgmt.GetUserAzureGroupsAsync(id);
        return Ok(ApiResponse.Ok(groups));
    }

    // ========== OPERACIONES MASIVAS ==========

    /// <summary>
    /// Crear múltiples usuarios en Azure AD
    /// </summary>
    [HttpPost("users/bulk-create")]
    public async Task<IActionResult> BulkCreateUsers([FromBody] IEnumerable<CreateAzureUserDto> users)
    {
        try
        {
            var result = await _azureMgmt.BulkCreateUsersAsync(users);
            return Ok(ApiResponse.Ok(result, "Operación masiva completada"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error in bulk create: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    /// <summary>
    /// Agregar múltiples usuarios a un grupo
    /// </summary>
    [HttpPost("groups/{groupId}/members/bulk-add")]
    public async Task<IActionResult> BulkAddUsersToGroup(string groupId, [FromBody] IEnumerable<string> userIds)
    {
        try
        {
            var result = await _azureMgmt.BulkAddUsersToGroupAsync(groupId, userIds);
            return Ok(ApiResponse.Ok(result, "Operación masiva completada"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error in bulk add to group: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }

    // ========== SINCRONIZACIÓN ==========

    /// <summary>
    /// Sincronizar un usuario de Azure AD con la base de datos local
    /// Sincronizar un usuario de Azure AD con la base de datos local
    /// </summary>
    [HttpPost("sync/user/{id}")]
    public async Task<IActionResult> SyncUserToLocalDb(string id)
    {
        try
        {
            var result = await _azureMgmt.SyncUserToLocalDbAsync(id);
            return Ok(ApiResponse.Ok(result, "Sincronización completada"));
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error syncing user: {ex.Message}");
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
    }
}
