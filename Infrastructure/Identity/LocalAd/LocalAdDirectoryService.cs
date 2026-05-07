using Microsoft.Extensions.Options;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd
{
    /// <summary>
    /// CRUD de usuarios y grupos en Active Directory local vía LDAP.
    /// Usa la cuenta de servicio configurada en LocalAdOptions para todas las operaciones de directorio.
    /// </summary>
    public sealed class LocalAdDirectoryService : IDirectoryService
    {
        private readonly LocalAdOptions _opts;
        private readonly ILogger<LocalAdDirectoryService> _logger;

        public string ProviderName => "LocalAd";

        public LocalAdDirectoryService(IOptions<LocalAdOptions> opts, ILogger<LocalAdDirectoryService> logger)
        {
            _opts = opts.Value;
            _logger = logger;
        }

        public async Task<DirectoryUser?> GetUserAsync(string id, CancellationToken ct = default)
            => await Task.Run(() => SearchSingleUser($"(objectGUID={EscapeGuidFilter(id)})", ct), ct);

        public async Task<DirectoryUser?> GetUserByEmailAsync(string email, CancellationToken ct = default)
        {
            var esc = EscapeLdap(email);
            return await Task.Run(() =>
                SearchSingleUser($"(&(objectClass=user)(|(userPrincipalName={esc})(mail={esc})))", ct), ct);
        }

        public async Task<IReadOnlyList<DirectoryUser>> ListUsersAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default)
        {
            var ldapFilter = string.IsNullOrWhiteSpace(filter)
                ? "(&(objectClass=user)(objectCategory=person))"
                : $"(&(objectClass=user)(objectCategory=person)(|(cn=*{EscapeLdap(filter)}*)(mail=*{EscapeLdap(filter)}*)(sAMAccountName=*{EscapeLdap(filter)}*)))";

            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var attrs = UserAttributes();
                var req = new SearchRequest(_opts.BaseDn, ldapFilter, SearchScope.Subtree, attrs);
                var resp = (SearchResponse)conn.SendRequest(req);

                return resp.Entries
                    .Cast<SearchResultEntry>()
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(MapUser)
                    .ToList() as IReadOnlyList<DirectoryUser>;
            }, ct);
        }

        public async Task<DirectoryUser> CreateUserAsync(DirectoryUser user, string initialPassword, bool forcePasswordChange = true, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var cn = user.DisplayName.Replace(",", "\\,");
                var dn = $"CN={cn},{_opts.UsersOu}";
                var upn = user.Email.Contains('@') ? user.Email : $"{user.Email}@{_opts.NetBiosDomain}";
                var sam = upn.Split('@')[0];

                var addReq = new AddRequest(dn,
                    new DirectoryAttribute("objectClass", "user"),
                    new DirectoryAttribute("cn", cn),
                    new DirectoryAttribute("displayName", user.DisplayName),
                    new DirectoryAttribute("userPrincipalName", upn),
                    new DirectoryAttribute("sAMAccountName", sam),
                    new DirectoryAttribute("mail", user.Email),
                    new DirectoryAttribute("givenName", user.GivenName ?? ""),
                    new DirectoryAttribute("sn", user.Surname ?? ""),
                    new DirectoryAttribute("department", user.Department ?? ""),
                    new DirectoryAttribute("title", user.JobTitle ?? ""),
                    // 514 = NORMAL_ACCOUNT | DISABLED (habilitado después de setear contraseña)
                    new DirectoryAttribute("userAccountControl", "514"));
                conn.SendRequest(addReq);

                // Set password via unicodePwd
                SetPasswordInternal(conn, dn, initialPassword);

                // Enable account: 512 = NORMAL_ACCOUNT, 65536 = PASSWORD_NOT_REQUIRED
                var uacValue = forcePasswordChange ? "8388608" : "512"; // 8388608 = PASSWD_NOTREQD cleared + must change
                var modReq = new ModifyRequest(dn,
                    DirectoryAttributeOperation.Replace, "userAccountControl", uacValue);
                conn.SendRequest(modReq);

                if (forcePasswordChange)
                {
                    var pwdLastSet = new ModifyRequest(dn,
                        DirectoryAttributeOperation.Replace, "pwdLastSet", "0");
                    conn.SendRequest(pwdLastSet);
                }

                _logger.LogInformation("AD local: usuario creado {Dn}", dn);
                return SearchSingleUser($"(userPrincipalName={EscapeLdap(upn)})", ct)
                    ?? throw new InvalidOperationException($"Usuario creado pero no encontrado: {upn}");
            }, ct);
        }

        public async Task<DirectoryUser> UpdateUserAsync(string id, DirectoryUser updated, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var dn = GetDnById(conn, id)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD: {id}");

                var mods = new List<DirectoryAttributeModification>
                {
                    Mod("displayName", updated.DisplayName),
                    Mod("givenName", updated.GivenName ?? ""),
                    Mod("sn", updated.Surname ?? ""),
                    Mod("title", updated.JobTitle ?? ""),
                    Mod("department", updated.Department ?? "")
                };

                var req = new ModifyRequest(dn, mods.ToArray());
                conn.SendRequest(req);

                _logger.LogInformation("AD local: usuario actualizado {Id}", id);
                return SearchSingleUser($"(objectGUID={EscapeGuidFilter(id)})", ct)!;
            }, ct);
        }

        public async Task SetUserEnabledAsync(string id, bool enabled, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var dn = GetDnById(conn, id)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD: {id}");

                // 512 = enabled, 514 = disabled (512 | 2)
                var uac = enabled ? "512" : "514";
                var req = new ModifyRequest(dn,
                    DirectoryAttributeOperation.Replace, "userAccountControl", uac);
                conn.SendRequest(req);
                _logger.LogInformation("AD local: usuario {Id} {Action}", id, enabled ? "habilitado" : "deshabilitado");
            }, ct);
        }

        public async Task DeleteUserAsync(string id, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var dn = GetDnById(conn, id)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD: {id}");
                conn.SendRequest(new DeleteRequest(dn));
                _logger.LogInformation("AD local: usuario eliminado {Id}", id);
            }, ct);
        }

        public async Task<DirectoryGroup?> GetGroupAsync(string id, CancellationToken ct = default)
            => await Task.Run(() => SearchSingleGroup($"(objectGUID={EscapeGuidFilter(id)})"), ct);

        public async Task<IReadOnlyList<DirectoryGroup>> ListGroupsAsync(int page = 1, int pageSize = 50, string? filter = null, CancellationToken ct = default)
        {
            var ldapFilter = string.IsNullOrWhiteSpace(filter)
                ? "(objectClass=group)"
                : $"(&(objectClass=group)(cn=*{EscapeLdap(filter)}*))";

            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var req = new SearchRequest(_opts.BaseDn, ldapFilter, SearchScope.Subtree,
                    "objectGUID", "cn", "description", "mail");
                var resp = (SearchResponse)conn.SendRequest(req);

                return resp.Entries
                    .Cast<SearchResultEntry>()
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(MapGroup)
                    .ToList() as IReadOnlyList<DirectoryGroup>;
            }, ct);
        }

        public async Task AddUserToGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var groupDn = GetGroupDnById(conn, groupId)
                    ?? throw new KeyNotFoundException($"Grupo no encontrado: {groupId}");
                var userDn = GetDnById(conn, userId)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado: {userId}");

                var req = new ModifyRequest(groupDn,
                    DirectoryAttributeOperation.Add, "member", userDn);
                conn.SendRequest(req);
                _logger.LogInformation("AD local: usuario {UserId} agregado al grupo {GroupId}", userId, groupId);
            }, ct);
        }

        public async Task RemoveUserFromGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var groupDn = GetGroupDnById(conn, groupId)
                    ?? throw new KeyNotFoundException($"Grupo no encontrado: {groupId}");
                var userDn = GetDnById(conn, userId)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado: {userId}");

                var req = new ModifyRequest(groupDn,
                    DirectoryAttributeOperation.Delete, "member", userDn);
                conn.SendRequest(req);
                _logger.LogInformation("AD local: usuario {UserId} removido del grupo {GroupId}", userId, groupId);
            }, ct);
        }

        public async Task<IReadOnlyList<DirectoryGroup>> GetUserGroupsAsync(string userId, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var userDn = GetDnById(conn, userId);
                if (userDn is null) return (IReadOnlyList<DirectoryGroup>)Array.Empty<DirectoryGroup>();

                var escaped = EscapeLdap(userDn);
                var req = new SearchRequest(_opts.BaseDn,
                    $"(&(objectClass=group)(member={escaped}))",
                    SearchScope.Subtree, "objectGUID", "cn", "description", "mail");
                var resp = (SearchResponse)conn.SendRequest(req);

                return resp.Entries
                    .Cast<SearchResultEntry>()
                    .Select(MapGroup)
                    .ToList() as IReadOnlyList<DirectoryGroup>;
            }, ct);
        }

        public async Task<bool> IsUserInGroupAsync(string groupId, string userId, CancellationToken ct = default)
        {
            var groups = await GetUserGroupsAsync(userId, ct);
            return groups.Any(g => g.Id == groupId);
        }

        // ── Helpers ────────────────────────────────────────────────────────────

        private LdapConnection BuildServiceConnection()
        {
            // Detecta formato de credencial para elegir AuthType:
            // - DN completo (contiene '=')  → Basic
            // - UPN (contiene '@')          → Basic  (funciona sin domain-join)
            // - NetBIOS 'DOMAIN\user'       → Negotiate
            // - username simple             → Basic con UPN construido: user@domain
            AuthType authType;
            string bindUser;

            if (_opts.ServiceAccountDn.Contains('='))
            {
                authType = AuthType.Basic;
                bindUser = _opts.ServiceAccountDn;
            }
            else if (_opts.ServiceAccountDn.Contains('@'))
            {
                authType = AuthType.Basic;
                bindUser = _opts.ServiceAccountDn;
            }
            else if (_opts.ServiceAccountDn.Contains('\\'))
            {
                authType = AuthType.Negotiate;
                bindUser = _opts.ServiceAccountDn;
            }
            else
            {
                // Username simple: construye UPN a partir del BaseDn (DC=uta,DC=edu,DC=ec → uta.edu.ec)
                var domain = string.Join(".", _opts.BaseDn
                    .Split(',')
                    .Where(p => p.TrimStart().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    .Select(p => p.TrimStart()[3..]));
                authType = AuthType.Basic;
                bindUser = string.IsNullOrWhiteSpace(domain)
                    ? _opts.ServiceAccountDn
                    : $"{_opts.ServiceAccountDn}@{domain}";
            }

            _logger.LogDebug("LDAP bind: servidor={Server}:{Port} usuario={User} authType={AuthType}",
                _opts.Server, _opts.Port, bindUser, authType);

            var id = new LdapDirectoryIdentifier(_opts.Server, _opts.Port, false, false);
            var creds = new NetworkCredential(bindUser, _opts.ServiceAccountPassword);
            var conn = new LdapConnection(id, creds, authType)
            {
                Timeout = TimeSpan.FromSeconds(_opts.TimeoutSeconds)
            };
            conn.SessionOptions.ProtocolVersion = 3;
            try
            {
                conn.Bind();
            }
            catch (LdapException ex)
            {
                _logger.LogError("LDAP bind fallido: errorCode={ErrorCode} mensaje={Message} usuario={User} servidor={Server}:{Port}",
                    ex.ErrorCode, ex.Message, bindUser, _opts.Server, _opts.Port);
                throw;
            }
            return conn;
        }

        private DirectoryUser? SearchSingleUser(string filter, CancellationToken ct)
        {
            using var conn = BuildServiceConnection();
            var req = new SearchRequest(_opts.BaseDn, filter, SearchScope.Subtree, UserAttributes());
            var resp = (SearchResponse)conn.SendRequest(req);
            return resp.Entries.Count == 0 ? null : MapUser(resp.Entries[0]);
        }

        private DirectoryGroup? SearchSingleGroup(string filter)
        {
            using var conn = BuildServiceConnection();
            var req = new SearchRequest(_opts.BaseDn, filter, SearchScope.Subtree,
                "objectGUID", "cn", "description", "mail");
            var resp = (SearchResponse)conn.SendRequest(req);
            return resp.Entries.Count == 0 ? null : MapGroup(resp.Entries[0]);
        }

        private string? GetDnById(LdapConnection conn, string objectId)
        {
            var req = new SearchRequest(_opts.BaseDn,
                $"(objectGUID={EscapeGuidFilter(objectId)})",
                SearchScope.Subtree, "distinguishedName");
            var resp = (SearchResponse)conn.SendRequest(req);
            if (resp.Entries.Count == 0) return null;
            return resp.Entries[0].DistinguishedName;
        }

        private string? GetGroupDnById(LdapConnection conn, string groupId)
        {
            var req = new SearchRequest(_opts.BaseDn,
                $"(&(objectClass=group)(objectGUID={EscapeGuidFilter(groupId)}))",
                SearchScope.Subtree, "distinguishedName");
            var resp = (SearchResponse)conn.SendRequest(req);
            if (resp.Entries.Count == 0) return null;
            return resp.Entries[0].DistinguishedName;
        }

        private static void SetPasswordInternal(LdapConnection conn, string dn, string password)
        {
            // unicodePwd requires LDAPS (port 636). Password must be wrapped in quotes and encoded as UTF-16LE.
            var encoded = Encoding.Unicode.GetBytes($"\"{password}\"");
            var req = new ModifyRequest(dn,
                DirectoryAttributeOperation.Replace, "unicodePwd", encoded);
            conn.SendRequest(req);
        }

        private static DirectoryUser MapUser(SearchResultEntry e)
        {
            string Attr(string name) => e.Attributes[name]?.Count > 0
                ? e.Attributes[name][0]?.ToString() ?? ""
                : "";

            var guidBytes = e.Attributes["objectGUID"]?.Count > 0
                ? (byte[])e.Attributes["objectGUID"][0]
                : null;
            var id = guidBytes is not null ? new Guid(guidBytes).ToString() : e.DistinguishedName;

            return new DirectoryUser(
                id,
                Attr("mail").Length > 0 ? Attr("mail") : Attr("userPrincipalName"),
                Attr("displayName"),
                Attr("givenName").Length > 0 ? Attr("givenName") : null,
                Attr("sn").Length > 0 ? Attr("sn") : null,
                Attr("title").Length > 0 ? Attr("title") : null,
                Attr("department").Length > 0 ? Attr("department") : null,
                !Attr("userAccountControl").StartsWith("514"),
                null);
        }

        private static DirectoryGroup MapGroup(SearchResultEntry e)
        {
            string Attr(string name) => e.Attributes[name]?.Count > 0
                ? e.Attributes[name][0]?.ToString() ?? ""
                : "";

            var guidBytes = e.Attributes["objectGUID"]?.Count > 0
                ? (byte[])e.Attributes["objectGUID"][0]
                : null;
            var id = guidBytes is not null ? new Guid(guidBytes).ToString() : e.DistinguishedName;

            return new DirectoryGroup(
                id,
                Attr("cn"),
                Attr("description").Length > 0 ? Attr("description") : null,
                Attr("mail").Length > 0 ? Attr("mail") : null);
        }

        private static string[] UserAttributes() =>
            ["objectGUID", "displayName", "mail", "userPrincipalName", "sAMAccountName",
             "givenName", "sn", "department", "title", "userAccountControl"];

        private static DirectoryAttributeModification Mod(string attr, string value) =>
            new() { Name = attr, Operation = DirectoryAttributeOperation.Replace, [0] = value };

        private static string EscapeLdap(string value) =>
            value.Replace("\\", "\\5c").Replace("*", "\\2a")
                 .Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");

        /// <summary>Convierte un GUID string al formato escapado para filtros LDAP (octetos con backslash).</summary>
        private static string EscapeGuidFilter(string guidStr)
        {
            if (!Guid.TryParse(guidStr, out var guid)) return EscapeLdap(guidStr);
            return string.Concat(guid.ToByteArray().Select(b => $"\\{b:x2}"));
        }
    }
}
