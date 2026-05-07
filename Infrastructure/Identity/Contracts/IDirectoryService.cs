namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    /// <summary>CRUD de usuarios y grupos en un directorio (Entra ID o AD local).</summary>
    public interface IDirectoryService
    {
        string ProviderName { get; }

        Task<DirectoryUser?> GetUserAsync(string id, CancellationToken ct = default);
        Task<DirectoryUser?> GetUserByEmailAsync(string email, CancellationToken ct = default);
        Task<IReadOnlyList<DirectoryUser>> ListUsersAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default);
        Task<DirectoryUser> CreateUserAsync(DirectoryUser user, string initialPassword, bool forcePasswordChange = true, CancellationToken ct = default);
        Task<DirectoryUser> UpdateUserAsync(string id, DirectoryUser updated, CancellationToken ct = default);
        Task SetUserEnabledAsync(string id, bool enabled, CancellationToken ct = default);
        Task DeleteUserAsync(string id, CancellationToken ct = default);

        Task<DirectoryGroup?> GetGroupAsync(string id, CancellationToken ct = default);
        Task<IReadOnlyList<DirectoryGroup>> ListGroupsAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default);
        Task AddUserToGroupAsync(string groupId, string userId, CancellationToken ct = default);
        Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken ct = default);
        Task<IReadOnlyList<DirectoryGroup>> GetUserGroupsAsync(string userId, CancellationToken ct = default);
        Task<bool> IsUserInGroupAsync(string groupId, string userId, CancellationToken ct = default);
    }
}
