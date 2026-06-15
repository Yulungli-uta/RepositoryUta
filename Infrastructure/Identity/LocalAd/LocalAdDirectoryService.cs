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

        private const int MaxCnAttempts = 10;

        public async Task<DirectoryUser> CreateUserAsync(DirectoryUser user, string initialPassword, string targetOu, bool forcePasswordChange = true, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(targetOu))
                throw new InvalidOperationException(
                    "targetOu no puede estar vacío al crear usuario en AD Local. " +
                    "Verifique LocalAd:FuncionariosActivosOu o LocalAd:EstudiantesActivosOu en appsettings.json.");

            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var upn = user.Email.Contains('@') ? user.Email : $"{user.Email}@{_opts.NetBiosDomain}";
                // sAMAccountName: límite 20 chars en AD
                var sam = upn.Split('@')[0];
                if (sam.Length > 20) sam = sam[..20];

                // Verificar que no existe otro usuario con el mismo UPN o mail
                var existingByUpn = SearchSingleUser(
                    $"(&(objectClass=user)(|(userPrincipalName={EscapeLdap(upn)})(mail={EscapeLdap(user.Email)})))", ct);
                if (existingByUpn is not null)
                    throw new InvalidOperationException(
                        $"Ya existe un usuario en AD Local con UPN '{upn}' o email '{user.Email}' (objectGUID={existingByUpn.Id}).");

                // ── Bucle de creación con CN único ────────────────────────────────
                // Si CN=DisplayName ya existe en el OU (usuario con mismo nombre),
                // se reintenta con sufijo numérico: "María Lozano" → "María Lozano 1" → "María Lozano 2"
                var baseCn   = user.DisplayName.Trim().Replace(",", "\\,");
                string? cnWarning = null;
                string usedCn;
                string usedDn;

                for (var attempt = 0; attempt <= MaxCnAttempts; attempt++)
                {
                    usedCn  = attempt == 0 ? baseCn : $"{baseCn} {attempt}";
                    usedDn  = $"CN={usedCn},{targetOu}";

                    var addReq = new AddRequest(usedDn,
                        new DirectoryAttribute("objectClass",        "user"),
                        new DirectoryAttribute("cn",                 usedCn),
                        new DirectoryAttribute("displayName",        user.DisplayName),
                        new DirectoryAttribute("userPrincipalName",  upn),
                        new DirectoryAttribute("sAMAccountName",     sam),
                        new DirectoryAttribute("mail",               user.Email),
                        // 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE — se habilita tras setear contraseña
                        new DirectoryAttribute("userAccountControl", "514"));

                    if (!string.IsNullOrWhiteSpace(user.GivenName))
                        addReq.Attributes.Add(new DirectoryAttribute("givenName", user.GivenName));
                    if (!string.IsNullOrWhiteSpace(user.Surname))
                        addReq.Attributes.Add(new DirectoryAttribute("sn", user.Surname));
                    if (!string.IsNullOrWhiteSpace(user.Department))
                        addReq.Attributes.Add(new DirectoryAttribute("department", user.Department));
                    if (!string.IsNullOrWhiteSpace(user.JobTitle))
                        addReq.Attributes.Add(new DirectoryAttribute("title", user.JobTitle));
                    if (!string.IsNullOrWhiteSpace(user.IdCard))
                        addReq.Attributes.Add(new DirectoryAttribute("employeeID", user.IdCard));

                    try
                    {
                        conn.SendRequest(addReq);

                        // ── Creación exitosa ──────────────────────────────────────
                        if (attempt > 0)
                        {
                            cnWarning = $"CN '{baseCn}' ya existía en AD Local ({attempt} intento(s)). " +
                                        $"Se usó CN '{usedCn}' para evitar conflicto.";
                            _logger.LogWarning(
                                "[AD-CREATE] ⚠ CN ajustado automáticamente. " +
                                "CN original='{OriginalCn}' | CN usado='{UsedCn}' | UPN={Upn}",
                                baseCn, usedCn, upn);
                        }

                        // Set password vía unicodePwd (requiere LDAPS / puerto 636)
                        SetPasswordInternal(usedDn, initialPassword);

                        // Habilitar cuenta: 512 = NORMAL_ACCOUNT
                        conn.SendRequest(new ModifyRequest(usedDn,
                            DirectoryAttributeOperation.Replace, "userAccountControl", "512"));

                        if (forcePasswordChange)
                        {
                            // pwdLastSet = 0 fuerza cambio de contraseña en el primer inicio de sesión
                            conn.SendRequest(new ModifyRequest(usedDn,
                                DirectoryAttributeOperation.Replace, "pwdLastSet", "0"));
                        }

                        _logger.LogInformation(
                            "[AD-CREATE] ✓ Usuario creado. DN={Dn} | UPN={Upn} | OU={OU}",
                            usedDn, upn, targetOu);

                        var created = SearchSingleUser($"(userPrincipalName={EscapeLdap(upn)})", ct)
                            ?? throw new InvalidOperationException(
                                $"Usuario creado pero no encontrado por UPN '{upn}'.");

                        // Retornar con CnWarning para que la capa superior pueda notificar al frontend
                        return created with { CnWarning = cnWarning };
                    }
                    catch (DirectoryOperationException ex)
                        when (ex.Response?.ResultCode == ResultCode.EntryAlreadyExists)
                    {
                        // CN ocupado → reintentar con sufijo numérico
                        _logger.LogWarning(
                            "[AD-CREATE] CN '{Cn}' ya existe en AD (intento {Attempt}/{Max}). " +
                            "Reintentando con sufijo numérico. UPN={Upn}",
                            usedCn, attempt, MaxCnAttempts, upn);
                    }
                }

                throw new InvalidOperationException(
                    $"No se pudo crear el usuario '{upn}' en AD Local: " +
                    $"los {MaxCnAttempts} candidatos de CN basados en '{baseCn}' ya están ocupados.");
            }, ct);
        }

        public async Task MoveUserToOuAsync(string userObjectId, string targetOuDn, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var currentDn = GetDnById(conn, userObjectId)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD para mover OU: {userObjectId}");

                // Extraer el RDN (ej: "CN=Juan Pérez") del DN actual
                var rdn = currentDn.Split(',')[0];

                // ModifyDNRequest(currentDn, newParentOu, newRdn)
                var req = new ModifyDNRequest(currentDn, targetOuDn, rdn)
                {
                    DeleteOldRdn = true
                };
                conn.SendRequest(req);

                _logger.LogInformation("[AD-MOVE] Usuario {ObjectId} movido a {TargetOu}", userObjectId, targetOuDn);
            }, ct);
        }

        public async Task<DirectoryUser> UpdateUserAsync(string id, DirectoryUser updated, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var dn = GetDnById(conn, id)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD: {id}");

                var mods = new List<DirectoryAttributeModification> { Mod("displayName", updated.DisplayName) };
                if (!string.IsNullOrWhiteSpace(updated.GivenName)) mods.Add(Mod("givenName", updated.GivenName!));
                if (!string.IsNullOrWhiteSpace(updated.Surname)) mods.Add(Mod("sn", updated.Surname!));
                if (!string.IsNullOrWhiteSpace(updated.JobTitle)) mods.Add(Mod("title", updated.JobTitle!));
                if (!string.IsNullOrWhiteSpace(updated.Department)) mods.Add(Mod("department", updated.Department!));

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
                var groupDn = ResolveGroupDn(conn, groupId)
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
                var groupDn = ResolveGroupDn(conn, groupId)
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
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var groupDn = ResolveGroupDn(conn, groupId);
                if (groupDn is null) return false;

                var userDn = GetDnById(conn, userId);
                if (userDn is null) return false;

                // Buscar directamente en el atributo member del grupo (más confiable que filtro)
                var req = new SearchRequest(groupDn, "(objectClass=group)", SearchScope.Base, "member");
                var resp = (SearchResponse)conn.SendRequest(req);
                if (resp.Entries.Count == 0) return false;

                var memberAttr = resp.Entries[0].Attributes["member"];
                if (memberAttr == null || memberAttr.Count == 0) return false;

                return Enumerable.Range(0, memberAttr.Count)
                    .Select(i => memberAttr[i]?.ToString() ?? "")
                    .Any(m => string.Equals(m, userDn, StringComparison.OrdinalIgnoreCase));
            }, ct);
        }

        public async Task<DirectoryGroup> CreateGroupAsync(string groupName, string? description, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var cn = groupName.Replace(",", "\\,");
                var dn = $"CN={cn},{_opts.GroupsOu}";
                var sam = cn.Length > 20 ? cn[..20] : cn;

                var addReq = new AddRequest(dn,
                    new DirectoryAttribute("objectClass", "group"),
                    new DirectoryAttribute("cn", cn),
                    new DirectoryAttribute("sAMAccountName", sam),
                    // -2147483646 = Global Security Group
                    new DirectoryAttribute("groupType", "-2147483646"));

                if (!string.IsNullOrWhiteSpace(description))
                    addReq.Attributes.Add(new DirectoryAttribute("description", description));

                conn.SendRequest(addReq);
                _logger.LogInformation("AD local: grupo creado {Dn}", dn);

                return SearchSingleGroup($"(cn={EscapeLdap(cn)})")
                    ?? throw new InvalidOperationException($"Grupo creado pero no encontrado: {cn}");
            }, ct);
        }

        public async Task ChangeUserPasswordAsync(string userId, string newPassword, bool forcePasswordChange, CancellationToken ct = default)
        {
            await Task.Run(() =>
            {
                using var conn = BuildServiceConnection();
                var dn = GetDnById(conn, userId)
                    ?? throw new KeyNotFoundException($"Usuario no encontrado en AD: {userId}");

                SetPasswordInternal(dn, newPassword);

                if (forcePasswordChange)
                {
                    var req = new ModifyRequest(dn,
                        DirectoryAttributeOperation.Replace, "pwdLastSet", "0");
                    conn.SendRequest(req);
                }

                _logger.LogInformation("AD local: contraseña restablecida para {Id}", userId);
            }, ct);
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

        /// <summary>
        /// Busca el DN de un usuario por objectGUID o, como fallback, por UPN/mail/sAMAccountName.
        /// Esto permite pasar tanto GUIDs como emails a los métodos de AD sin conversión previa.
        /// </summary>
        private string? GetDnById(LdapConnection conn, string objectId)
        {
            // Intento 1: búsqueda por objectGUID (camino rápido)
            if (Guid.TryParse(objectId, out _))
            {
                var req1 = new SearchRequest(_opts.BaseDn,
                    $"(objectGUID={EscapeGuidFilter(objectId)})",
                    SearchScope.Subtree, "distinguishedName");
                var resp1 = (SearchResponse)conn.SendRequest(req1);
                if (resp1.Entries.Count > 0) return resp1.Entries[0].DistinguishedName;
            }

            // Intento 2: búsqueda por UPN, mail o sAMAccountName (fallback para emails)
            var esc = EscapeLdap(objectId);
            var req2 = new SearchRequest(_opts.BaseDn,
                $"(&(objectClass=user)(|(userPrincipalName={esc})(mail={esc})(sAMAccountName={esc})))",
                SearchScope.Subtree, "distinguishedName");
            var resp2 = (SearchResponse)conn.SendRequest(req2);
            return resp2.Entries.Count == 0 ? null : resp2.Entries[0].DistinguishedName;
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

        /// <summary>
        /// Resuelve el DN de un grupo buscando por objectGUID (si es un GUID válido) o por CN (nombre).
        /// Permite configurar grupos por nombre legible (ej: "UActivos") en lugar de GUIDs.
        /// </summary>
        private string? ResolveGroupDn(LdapConnection conn, string cnOrId)
        {
            // Intento 1: por objectGUID
            if (Guid.TryParse(cnOrId, out _))
                return GetGroupDnById(conn, cnOrId);

            // Intento 2: por CN (nombre del grupo)
            var req = new SearchRequest(_opts.BaseDn,
                $"(&(objectClass=group)(cn={EscapeLdap(cnOrId)}))",
                SearchScope.Subtree, "distinguishedName");
            var resp = (SearchResponse)conn.SendRequest(req);
            return resp.Entries.Count == 0 ? null : resp.Entries[0].DistinguishedName;
        }

        /// <summary>
        /// Establece o reemplaza unicodePwd via una conexión LDAPS independiente (SSL obligatorio).
        /// AD rechaza unicodePwd en canales no cifrados con WILL_NOT_PERFORM.
        /// </summary>
        private void SetPasswordInternal(string dn, string password)
        {
            using var conn = BuildPasswordConnection();
            var encoded = Encoding.Unicode.GetBytes($"\"{password}\"");
            var req = new ModifyRequest(dn,
                DirectoryAttributeOperation.Replace, "unicodePwd", encoded);
            conn.SendRequest(req);
        }

        /// <summary>Conexión LDAPS (SSL) usada exclusivamente para operaciones de contraseña (unicodePwd).</summary>
        private LdapConnection BuildPasswordConnection()
        {
            // Reutiliza la misma lógica de credenciales que BuildServiceConnection
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
                var domain = string.Join(".", _opts.BaseDn
                    .Split(',')
                    .Where(p => p.TrimStart().StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    .Select(p => p.TrimStart()[3..]));
                authType = AuthType.Basic;
                bindUser = string.IsNullOrWhiteSpace(domain)
                    ? _opts.ServiceAccountDn
                    : $"{_opts.ServiceAccountDn}@{domain}";
            }

            var id = new LdapDirectoryIdentifier(_opts.Server, _opts.LdapsPort, false, false);
            var creds = new NetworkCredential(bindUser, _opts.ServiceAccountPassword);
            var conn = new LdapConnection(id, creds, authType)
            {
                Timeout = TimeSpan.FromSeconds(_opts.TimeoutSeconds)
            };
            conn.SessionOptions.ProtocolVersion = 3;
            conn.SessionOptions.SecureSocketLayer = true;
            // Permite certificados autofirmados de DC interno
            conn.SessionOptions.VerifyServerCertificate = (_, _) => true;

            _logger.LogDebug("LDAPS bind (password): servidor={Server}:{Port} usuario={User}",
                _opts.Server, _opts.LdapsPort, bindUser);

            try
            {
                conn.Bind();
            }
            catch (LdapException ex)
            {
                _logger.LogError("LDAPS bind fallido: errorCode={ErrorCode} mensaje={Message}", ex.ErrorCode, ex.Message);
                throw;
            }
            return conn;
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
