using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IAzureManagementService
    {
        Task<AzureUserDto> CreateUserInAzureAsync(CreateAzureUserDto dto);
        Task<AzureUserDto?> GetUserFromAzureAsync(string azureObjectId);
        Task<AzureUserDto?> GetUserByEmailFromAzureAsync(string email);
        Task<AzureUserDto?> UpdateUserInAzureAsync(string azureObjectId, UpdateAzureUserDto dto);
        Task<bool> EnableDisableUserInAzureAsync(string azureObjectId, bool enable);
        Task<bool> DeleteUserFromAzureAsync(string azureObjectId, bool permanentDelete = false);
        Task<PagedResult<AzureUserDto>> ListUsersFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null);

        Task<string> ResetPasswordInAzureAsync(string azureObjectId, bool forceChange = true);
        Task<bool> ChangePasswordInAzureAsync(string azureObjectId, string newPassword, bool forceChangeNextSignIn = false);
        Task<PasswordValidationResult> ValidatePasswordPolicyAsync(string password);
        Task<string> GenerateSecurePasswordAsync();

        Task<IEnumerable<AzureRoleDto>> GetAllAzureDirectoryRolesAsync();
        Task<IEnumerable<AzureRoleDto>> GetUserAzureRolesAsync(string azureObjectId);
        Task<bool> AssignAzureRoleAsync(string azureObjectId, string roleId);
        Task<bool> RemoveAzureRoleAsync(string azureObjectId, string roleId);
        Task<IEnumerable<AzureUserDto>> GetRoleMembersAsync(string roleId);

        Task<AzureGroupDto> CreateGroupInAzureAsync(CreateAzureGroupDto dto);
        Task<AzureGroupDto?> GetGroupFromAzureAsync(string groupId);
        Task<AzureGroupDto?> UpdateGroupInAzureAsync(string groupId, UpdateAzureGroupDto dto);
        Task<bool> DeleteGroupFromAzureAsync(string groupId);
        Task<PagedResult<AzureGroupDto>> ListGroupsFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null);
        Task<bool> AddUserToAzureGroupAsync(string groupId, string azureObjectId);
        Task<bool> RemoveUserFromAzureGroupAsync(string groupId, string azureObjectId);
        Task<IEnumerable<AzureUserDto>> GetGroupMembersAsync(string groupId);
        Task<IEnumerable<AzureGroupDto>> GetUserAzureGroupsAsync(string azureObjectId);

        Task<BulkOperationResult> BulkCreateUsersAsync(IEnumerable<CreateAzureUserDto> users);
        Task<BulkOperationResult> BulkAddUsersToGroupAsync(string groupId, IEnumerable<string> userIds);

        Task<SyncResult> SyncUserToLocalDbAsync(string azureObjectId);

        /// <summary>
        /// Verifica si un usuario existe en Microsoft Entra usando su UPN (userPrincipalName).
        /// Se usa para determinar el estado de sincronización después de operaciones en AD Local.
        /// No crea ni modifica ningún objeto en Entra.
        /// </summary>
        Task<EntraSyncResult> CheckUserEntraSyncAsync(string upn);
    }
}
