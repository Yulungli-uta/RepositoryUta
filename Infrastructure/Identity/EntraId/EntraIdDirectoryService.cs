using Microsoft.Graph;
using Microsoft.Graph.Models;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.EntraId
{
    /// <summary>Implementación de IDirectoryService sobre Microsoft Graph (Entra ID).</summary>
    public sealed class EntraIdDirectoryService : IDirectoryService
    {
        private readonly GraphServiceClient _graph;
        private readonly IConfiguration _cfg;
        private readonly ILogger<EntraIdDirectoryService> _logger;

        public string ProviderName => "EntraId";

        public EntraIdDirectoryService(GraphServiceClient graph, IConfiguration cfg, ILogger<EntraIdDirectoryService> logger)
        {
            _graph = graph;
            _cfg = cfg;
            _logger = logger;
        }

        public async Task<DirectoryUser?> GetUserAsync(string id, CancellationToken ct = default)
        {
            try
            {
                var u = await _graph.Users[id].GetAsync(cancellationToken: ct);
                return u is null ? null : Map(u);
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph GetUser {Id}", id); return null; }
        }

        public async Task<DirectoryUser?> GetUserByEmailAsync(string email, CancellationToken ct = default)
        {
            try
            {
                var result = await _graph.Users.GetAsync(r =>
                {
                    r.QueryParameters.Filter = $"userPrincipalName eq '{email}'";
                    r.QueryParameters.Top = 1;
                }, ct);
                var u = result?.Value?.FirstOrDefault();
                return u is null ? null : Map(u);
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph GetUserByEmail {Email}", email); return null; }
        }

        public async Task<IReadOnlyList<DirectoryUser>> ListUsersAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default)
        {
            try
            {
                // Graph API no soporta $skip en /users; se usa client-side paging sobre el primer lote.
                var result = await _graph.Users.GetAsync(r =>
                {
                    r.QueryParameters.Top = pageSize * page;
                    if (!string.IsNullOrWhiteSpace(filter))
                        r.QueryParameters.Filter = filter;
                }, ct);
                return result?.Value?
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(Map).ToList() ?? [];
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph ListUsers"); return []; }
        }

        public async Task<DirectoryUser> CreateUserAsync(DirectoryUser user, string initialPassword, bool forcePasswordChange = true, CancellationToken ct = default)
        {
            var domain = _cfg["AzureAd:Domain"] ?? throw new InvalidOperationException("AzureAd:Domain no configurado.");
            var upn = user.Email.Contains('@') ? user.Email : $"{user.Email}@{domain}";

            var newUser = new User
            {
                DisplayName = user.DisplayName,
                GivenName = user.GivenName,
                Surname = user.Surname,
                UserPrincipalName = upn,
                MailNickname = upn.Split('@')[0],
                JobTitle = user.JobTitle,
                Department = user.Department,
                AccountEnabled = user.AccountEnabled,
                PasswordProfile = new PasswordProfile
                {
                    Password = initialPassword,
                    ForceChangePasswordNextSignIn = forcePasswordChange
                }
            };

            var created = await _graph.Users.PostAsync(newUser, cancellationToken: ct)
                ?? throw new InvalidOperationException("Graph no devolvió usuario creado.");
            _logger.LogInformation("Entra ID: usuario creado {Upn}", upn);
            return Map(created);
        }

        public async Task<DirectoryUser> UpdateUserAsync(string id, DirectoryUser updated, CancellationToken ct = default)
        {
            var patch = new User
            {
                DisplayName = updated.DisplayName,
                GivenName = updated.GivenName,
                Surname = updated.Surname,
                JobTitle = updated.JobTitle,
                Department = updated.Department
            };
            await _graph.Users[id].PatchAsync(patch, cancellationToken: ct);
            return (await GetUserAsync(id, ct))!;
        }

        public async Task SetUserEnabledAsync(string id, bool enabled, CancellationToken ct = default)
        {
            await _graph.Users[id].PatchAsync(new User { AccountEnabled = enabled }, cancellationToken: ct);
        }

        public async Task DeleteUserAsync(string id, CancellationToken ct = default)
        {
            await _graph.Users[id].DeleteAsync(cancellationToken: ct);
        }

        public async Task<DirectoryGroup?> GetGroupAsync(string id, CancellationToken ct = default)
        {
            try
            {
                var g = await _graph.Groups[id].GetAsync(cancellationToken: ct);
                return g is null ? null : MapGroup(g);
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph GetGroup {Id}", id); return null; }
        }

        public async Task<IReadOnlyList<DirectoryGroup>> ListGroupsAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default)
        {
            try
            {
                var result = await _graph.Groups.GetAsync(r =>
                {
                    r.QueryParameters.Top = pageSize;
                    r.QueryParameters.Skip = (page - 1) * pageSize;
                    if (!string.IsNullOrWhiteSpace(filter))
                        r.QueryParameters.Filter = filter;
                }, ct);
                return result?.Value?.Select(MapGroup).ToList() ?? [];
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph ListGroups"); return []; }
        }

        public async Task AddUserToGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            var refBody = new Microsoft.Graph.Models.ReferenceCreate
            {
                OdataId = $"https://graph.microsoft.com/v1.0/directoryObjects/{userId}"
            };
            await _graph.Groups[groupId].Members.Ref.PostAsync(refBody, cancellationToken: ct);
        }

        public async Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            await _graph.Groups[groupId].Members[userId].Ref.DeleteAsync(cancellationToken: ct);
        }

        public async Task<IReadOnlyList<DirectoryGroup>> GetUserGroupsAsync(string userId, CancellationToken ct = default)
        {
            try
            {
                var result = await _graph.Users[userId].MemberOf.GetAsync(cancellationToken: ct);
                return result?.Value?
                    .OfType<Group>()
                    .Select(MapGroup)
                    .ToList() ?? [];
            }
            catch (Exception ex) { _logger.LogError(ex, "Graph GetUserGroups {UserId}", userId); return []; }
        }

        public async Task<bool> IsUserInGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            var groups = await GetUserGroupsAsync(userId, ct);
            return groups.Any(g => g.Id == groupId);
        }

        private static DirectoryUser Map(User u) => new(
            u.Id ?? "",
            u.UserPrincipalName ?? u.Mail ?? "",
            u.DisplayName ?? "",
            u.GivenName,
            u.Surname,
            u.JobTitle,
            u.Department,
            u.AccountEnabled ?? false,
            u.CreatedDateTime);

        private static DirectoryGroup MapGroup(Group g) => new(
            g.Id ?? "",
            g.DisplayName ?? "",
            g.Description,
            g.Mail);
    }
}
