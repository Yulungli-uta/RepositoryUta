using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Utilities;
using WsSeguUta.AuthSystem.API.Security;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class AuthService : IAuthService
    {
        private readonly IUserRepository _users;
        private readonly IAuthRepository _auth;
        private readonly ITokenService _tokens;
        private readonly AuthDbContext _context;
        private readonly IConfiguration _cfg;
        private readonly ILogger<AuthService> _logger;
        private readonly IIdentityProviderResolver _identityResolver;
        private readonly RsaKeyProvider _keys;

        public AuthService(IUserRepository users, IAuthRepository auth, ITokenService tokens, AuthDbContext context, IConfiguration cfg, ILogger<AuthService> logger, IIdentityProviderResolver identityResolver, RsaKeyProvider keys)
        {
            _users = users;
            _auth = auth;
            _tokens = tokens;
            _context = context;
            _cfg = cfg;
            _logger = logger;
            _identityResolver = identityResolver;
            _keys = keys;
        }

        public async Task<TokenPair?> LoginLocalAsync(string email, string password, string? ipAddress = null, string? userAgent = null, string? deviceInfo = null, string? browserId = null)
        {
            var now = DateTime.Now;
            var u = await _users.FindByEmailAsync(email);
            if (u is null || !u.IsActive || !string.Equals(u.UserType, "Local", StringComparison.OrdinalIgnoreCase))
            {
                await _auth.RecordFailedAttemptAsync(email, null, null, "User not found/inactive");
                await _auth.InsertLoginAsync(null, email, false, "Local", "Failed", "User not found/inactive", null, ipAddress, userAgent, deviceInfo);
                return null;
            }

            var cred = await _users.GetLocalCredAsync(u.Id);
            if (cred is null)
            {
                await _auth.RecordFailedAttemptAsync(email, null, null, "No credentials");
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "No credentials", null, ipAddress, userAgent, deviceInfo);
                return null;
            }

            if (cred.IsLocked || (cred.LockedUntil.HasValue && cred.LockedUntil.Value > now))
            {
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Blocked", "Locked account", null, ipAddress, userAgent, deviceInfo);
                return null;
            }

            if (cred.PasswordExpiresAt.HasValue && cred.PasswordExpiresAt.Value <= now)
            {
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", "Failed", "Password expired", null, ipAddress, userAgent, deviceInfo);
                return null;
            }

            if (!PasswordHasher.Verify(password, cred.PasswordHash))
            {
                cred.FailedAttempts += 1;
                cred.LastFailedAttempt = now;
                if (cred.FailedAttempts >= 5)
                {
                    cred.LockedUntil = now.AddMinutes(30);
                    cred.IsLocked = true;
                }
                await _users.UpdateLocalCredAsync(cred);
                await _auth.RecordFailedAttemptAsync(email, null, null, "Invalid password");
                await _auth.InsertLoginAsync(u.Id, email, false, "Local", cred.IsLocked ? "Blocked" : "Failed", "Invalid password", null, ipAddress, userAgent, deviceInfo);
                return null;
            }

            cred.FailedAttempts = 0;
            cred.IsLocked = false;
            cred.LockedUntil = null;
            await _users.UpdateLocalCredAsync(cred);

            var roles = await _users.GetRolesAsync(u.Id);
            var adGroups = await GetAdGroupsAsync(u.Email);
            var hrEmployeeId = await _users.GetHrEmployeeIdAsync(u.Id);
            var newSessionId = Guid.NewGuid();
            var access = await _tokens.CreateAsync(u.Id, u.Email, roles, adGroups, hrEmployeeId, sessionId: newSessionId);
            var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var refreshHash = _tokens.Hash(refresh);
            var session = await _auth.CreateSessionAsync(u.Id, access, refreshHash, now.AddDays(7), deviceInfo, ipAddress, userAgent, browserId, sessionId: newSessionId);
            await _users.SetLastLoginAsync(u.Id, now);
            await _auth.InsertLoginAsync(u.Id, email, true, "Local", "Success", null, session.SessionId, ipAddress, userAgent, deviceInfo);
            _logger.LogInformation("Login exitoso para {Email}, SessionId: {SessionId}", email, session.SessionId);
            return new TokenPair(access, refresh);
        }

        public async Task<TokenPair?> RefreshAsync(string refreshToken)
        {
            var hash = _tokens.Hash(refreshToken);
            var found = await _auth.GetActiveSessionByRefreshHashAsync(hash);
            if (found is null)
            {
                // El hash no corresponde a ninguna sesión activa: puede ser un token
                // inválido/expirado normal o el reuso de un token ya rotado (robo).
                await DetectRefreshTokenReuseAsync(hash);
                return null;
            }
            var (sess, u) = found.Value;
            var roles = await _users.GetRolesAsync(u.Id);
            var adGroups = await GetAdGroupsAsync(u.Email);
            var hrEmployeeId = await _users.GetHrEmployeeIdAsync(u.Id);
            var newSessionId = Guid.NewGuid();
            var newAccess = await _tokens.CreateAsync(u.Id, u.Email, roles, adGroups, hrEmployeeId, sessionId: newSessionId);
            var newRefresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            var newHash = _tokens.Hash(newRefresh);
            var newExp = DateTime.Now.AddDays(7);
            await _auth.RevokeSessionAsync(sess.SessionId, "Rotated");
            await _auth.CreateSessionAsync(u.Id, newAccess, newHash, newExp, sess.DeviceInfo, sess.IpAddress, sess.UserAgent, sess.BrowserId, sessionId: newSessionId);
            return new TokenPair(newAccess, newRefresh);
        }

        // Ventana de gracia para refresh concurrentes legítimos (ej.: dos pestañas del
        // mismo navegador refrescando a la vez). Dentro de esta ventana el reuso no se
        // trata como robo para no desloguear a usuarios legítimos.
        private static readonly TimeSpan RefreshReuseGraceWindow = TimeSpan.FromSeconds(60);

        /// <summary>
        /// Detección de reuso de refresh tokens rotados (OAuth 2.0 Security BCP).
        /// Presentar un token que ya fue rotado es el indicador más fiable de robo de sesión:
        /// se revocan todas las sesiones activas del usuario y se registra el evento de
        /// seguridad. Es best-effort: un fallo aquí nunca altera la respuesta del refresh.
        /// </summary>
        private async Task DetectRefreshTokenReuseAsync(string refreshHash)
        {
            try
            {
                var rotated = await _auth.GetRotatedSessionByRefreshHashAsync(refreshHash);
                if (rotated is null) return; // hash desconocido: token inválido normal, sin acción

                // Sesiones rotadas antes de este cambio no tienen RevokedAt: sin dato fiable
                // de cuándo se rotó, no se castiga (evita falsos positivos tras el despliegue).
                if (rotated.RevokedAt is null) return;

                if (DateTime.Now - rotated.RevokedAt.Value <= RefreshReuseGraceWindow) return;

                var revokedCount = await _auth.RevokeAllActiveSessionsForUserAsync(rotated.UserId, "RefreshReuse");
                await _auth.InsertLoginAsync(rotated.UserId, string.Empty, false, "Refresh", "TokenReuse",
                    $"Reuso de refresh token rotado; {revokedCount} sesiones revocadas",
                    rotated.SessionId, rotated.IpAddress, rotated.UserAgent, rotated.DeviceInfo);

                _logger.LogWarning(
                    "Reuso de refresh token detectado. UserId: {UserId}, sesión origen: {SessionId}, sesiones revocadas: {Count}",
                    rotated.UserId, rotated.SessionId, revokedCount);
            }
            catch (Exception ex)
            {
                // Nunca convertir un refresh fallido en un error 500 por la detección
                _logger.LogError(ex, "Error en la detección de reuso de refresh token");
            }
        }

        public async Task<bool> LogoutAsync(string refreshToken)
        {
            var hash = _tokens.Hash(refreshToken);
            var found = await _auth.GetActiveSessionByRefreshHashAsync(hash);
            if (found is null) return true;
            await _auth.RevokeSessionAsync(found.Value.Sess.SessionId, "Logout");
            return true;
        }

        public async Task<object?> MeAsync(Guid userId)
        {
            var u = await _users.FindByIdAsync(userId);
            if (u is null) return null;
            var roles = await _users.GetRolesAsync(userId);
            var personnelEmail = await _users.GetPersonnelEmailAsync(userId);

            // Mismo cálculo que RolePermissionsController.GetEffectivePermissions — se duplica
            // aquí en vez de llamarse a sí mismo por HTTP (evita una vuelta de red innecesaria
            // ya que ambos corren en el mismo proceso/DbContext).
            var actionPermissions = await (
                from ur in _context.Roles
                where roles.Contains(ur.Name) && ur.IsActive && !ur.IsDeleted
                join rp in _context.RolePermissions on ur.Id equals rp.RoleId
                join p in _context.Permissions on rp.PermissionId equals p.Id
                where !p.IsDeleted
                select (p.Module + "." + p.Action).ToUpper()
            ).Distinct().ToListAsync();

            // Informativo únicamente: nombres de AccessProfile asignados al usuario. La
            // autorización real ya quedó expandida a UserRole al momento de asignar el perfil
            // (ver IAccessProfileAssignmentService) — esto no se usa para calcular permisos.
            var profiles = await (
                from uap in _context.UserAccessProfiles
                where uap.UserId == userId && !uap.IsDeleted
                join ap in _context.AccessProfiles on uap.AccessProfileId equals ap.Id
                where ap.IsActive && !ap.IsDeleted
                select ap.Name
            ).Distinct().ToListAsync();

            return new
            {
                u.Id,
                u.Email,
                PersonnelEmail = personnelEmail,
                u.DisplayName,
                u.UserType,
                u.LastLogin,
                Roles = roles,
                ActionPermissions = actionPermissions,
                Profiles = profiles
            };
        }

        public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string? clientId)
        {
            try
            {
                var jwtHandler = new JwtSecurityTokenHandler();
                if (jwtHandler.CanReadToken(token))
                {
                    _logger.LogDebug("Token recibido en formato JWT válido");

                    var issuer = _cfg["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
                    var audience = _cfg["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";

                    var validationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ValidIssuer = issuer,
                        ValidAudience = audience,
                        IssuerSigningKey = _keys.PublicKey,
                        ClockSkew = TimeSpan.Zero
                    };

                    try
                    {
                        var principal = jwtHandler.ValidateToken(token, validationParameters, out var validatedToken);
                        var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                        var rolesClaims = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
                        _logger.LogDebug("Claims del token: sub={UserId}, roles={Roles}", userIdClaim, string.Join(",", rolesClaims));

                        // Tokens emitidos antes de este chequeo no traen "sid" — se validan
                        // igual que siempre (sin esto, cualquier sesión activa quedaría
                        // deslogueada al desplegar este cambio).
                        var sidClaim = principal.FindFirst("sid")?.Value;
                        if (Guid.TryParse(sidClaim, out var sessionId))
                        {
                            var sessionActive = await _context.UserSessions
                                .AsNoTracking()
                                .Where(s => s.SessionId == sessionId)
                                .Select(s => (bool?)s.IsActive)
                                .FirstOrDefaultAsync();

                            if (sessionActive == false)
                            {
                                return new ValidateTokenResponse(
                                    IsValid: false,
                                    TokenType: "JWT",
                                    ExpiresAt: null,
                                    UserId: null,
                                    SessionId: sessionId,
                                    Message: "Sesión revocada",
                                    Email: string.Empty);
                            }
                        }

                        if (Guid.TryParse(userIdClaim, out var userId))
                        {
                            var user = await _users.FindByIdAsync(userId);
                            if (user != null && user.IsActive)
                            {
                                return new ValidateTokenResponse(
                                    IsValid: true,
                                    TokenType: "JWT",
                                    ExpiresAt: ((JwtSecurityToken)validatedToken).ValidTo,
                                    UserId: userId,
                                    SessionId: Guid.TryParse(sidClaim, out var sid) ? sid : null,
                                    Message: "Token is valid",
                                    Email: user.Email);
                            }
                        }

                        // Token de aplicacion (client_credentials): el "sub" es un tokenId
                        // aleatorio, no un usuario real - se identifica por el claim
                        // "client_id" y se resuelve contra auth.tbl_Applications en vez de
                        // auth.tbl_Users. Sin esta rama, cualquier token emitido por
                        // /api/app-auth/token (ej. el que usa signature-api para llamar a
                        // HrBackend) siempre habria fallado aqui.
                        var clientIdClaim = principal.FindFirst("client_id")?.Value;
                        if (!string.IsNullOrWhiteSpace(clientIdClaim))
                        {
                            var app = await _context.Applications.AsNoTracking()
                                .FirstOrDefaultAsync(a => a.ClientId == clientIdClaim && a.IsActive && !a.IsDeleted);
                            if (app is not null)
                            {
                                return new ValidateTokenResponse(
                                    IsValid: true,
                                    TokenType: "AppToken",
                                    ExpiresAt: ((JwtSecurityToken)validatedToken).ValidTo,
                                    UserId: null,
                                    SessionId: null,
                                    Message: "Token is valid",
                                    Email: app.ClientId);
                            }
                        }

                        _logger.LogWarning("Validación JWT fallida: usuario no encontrado o inactivo");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "User not found or inactive", null);
                    }
                    catch (SecurityTokenExpiredException)
                    {
                        _logger.LogInformation("Token JWT expirado");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token expired", null);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Validación JWT fallida");
                        return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token validation failed", null);
                    }
                }

                _logger.LogDebug("Token no es JWT, intentando como GUID de sesión");
                if (Guid.TryParse(token, out var tokenGuid))
                {
                    var session = await _context.UserSessions
                        .FirstOrDefaultAsync(s => s.SessionId == tokenGuid && s.IsActive && s.ExpiresAt > DateTime.Now);
                    if (session != null)
                        return new ValidateTokenResponse(true, "User token", session.ExpiresAt, session.UserId, session.SessionId, "Token is valid", null);
                }

                _logger.LogWarning("Token inválido o expirado");
                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Token is invalid or expired", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al validar token");
                return new ValidateTokenResponse(false, "Unknown", null, null, null, "Error validating token", null);
            }
        }

        public async Task<ChangePasswordResponse> ChangePasswordAsync(Guid userId, string currentPassword, string newPassword)
        {
            var user = await _users.FindByIdAsync(userId);
            if (user is null || !user.IsActive)
                return new ChangePasswordResponse(false, "Usuario no encontrado o inactivo");

            if (!string.Equals(user.UserType, "Local", StringComparison.OrdinalIgnoreCase))
                return new ChangePasswordResponse(false, "Este usuario es de tipo AD/Azure y no puede cambiar su contraseña desde aquí");

            var cred = await _users.GetLocalCredAsync(userId);
            if (cred is null)
                return new ChangePasswordResponse(false, "El usuario no tiene credenciales locales");

            if (!PasswordHasher.Verify(currentPassword, cred.PasswordHash))
                return new ChangePasswordResponse(false, "La contraseña actual es incorrecta");

            if (PasswordHasher.Verify(newPassword, cred.PasswordHash))
                return new ChangePasswordResponse(false, "La nueva contraseña no puede ser igual a la actual");

            if (!IsPasswordComplex(newPassword))
                return new ChangePasswordResponse(false, "La nueva contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número");

            await ApplyPasswordChangeAsync(userId, cred, newPassword);
            return new ChangePasswordResponse(true, "Contraseña cambiada exitosamente");
        }

        public async Task<RequestPasswordChange2FAResponse> RequestPasswordChange2FAAsync(Guid userId, bool isDevelopment = false)
        {
            var user = await _users.FindByIdAsync(userId);
            if (user is null || !user.IsActive)
                return new RequestPasswordChange2FAResponse(false, "Usuario no encontrado o inactivo");

            // Usuarios locales: verificar que tengan credenciales
            if (string.Equals(user.UserType, "Local", StringComparison.OrdinalIgnoreCase))
            {
                var cred = await _users.GetLocalCredAsync(userId);
                if (cred is null)
                    return new RequestPasswordChange2FAResponse(false, "El usuario no tiene credenciales locales");
            }

            // Invalida cualquier OTP previo pendiente para este usuario
            var existing = await _context.SecurityTokens
                .Where(t => t.UserId == userId && t.TokenType == "PasswordChange2FA" && !t.IsUsed && t.ExpiresAt > DateTime.Now)
                .ToListAsync();
            foreach (var t in existing) t.IsUsed = true;

            // Genera OTP de 6 dígitos
            var otpCode = GenerateOtp();
            var otpHash = _tokens.Hash(otpCode);

            _context.SecurityTokens.Add(new Models.Entities.SecurityToken
            {
                UserId = userId,
                TokenType = "PasswordChange2FA",
                TokenHash = otpHash,
                ExpiresAt = DateTime.Now.AddMinutes(10),
                AdditionalData = userId.ToString()
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation("OTP de cambio de contraseña generado para usuario {UserId}", userId);

            // En producción el código se enviaría por email/SMS — aquí solo lo exponemos en dev
            return new RequestPasswordChange2FAResponse(
                true,
                "Código OTP generado. Válido por 10 minutos.",
                isDevelopment ? otpCode : null);
        }

        public async Task<ChangePasswordResponse> ChangePasswordWith2FAAsync(Guid userId, string currentPassword, string newPassword, string otpCode)
        {
            var user = await _users.FindByIdAsync(userId);
            if (user is null || !user.IsActive || !string.Equals(user.UserType, "Local", StringComparison.OrdinalIgnoreCase))
                return new ChangePasswordResponse(false, "Usuario no válido para esta operación");

            var cred = await _users.GetLocalCredAsync(userId);
            if (cred is null)
                return new ChangePasswordResponse(false, "El usuario no tiene credenciales locales");

            if (!PasswordHasher.Verify(currentPassword, cred.PasswordHash))
            {
                _logger.LogWarning("Contraseña actual incorrecta en cambio 2FA para usuario {UserId}", userId);
                return new ChangePasswordResponse(false, "La contraseña actual es incorrecta");
            }

            if (!IsPasswordComplex(newPassword))
                return new ChangePasswordResponse(false, "La nueva contraseña no cumple los requisitos: mínimo 8 caracteres, una mayúscula y un número");

            if (PasswordHasher.Verify(newPassword, cred.PasswordHash))
                return new ChangePasswordResponse(false, "La nueva contraseña no puede ser igual a la actual");

            // Verifica OTP
            var otpHash = _tokens.Hash(otpCode);
            var token = await _context.SecurityTokens
                .FirstOrDefaultAsync(t =>
                    t.UserId == userId &&
                    t.TokenType == "PasswordChange2FA" &&
                    t.TokenHash == otpHash &&
                    !t.IsUsed &&
                    t.ExpiresAt > DateTime.Now);

            if (token is null)
            {
                _logger.LogWarning("OTP inválido o expirado en cambio 2FA para usuario {UserId}", userId);
                return new ChangePasswordResponse(false, "El código OTP es inválido o ha expirado");
            }

            token.IsUsed = true;
            await ApplyPasswordChangeAsync(userId, cred, newPassword);

            _logger.LogInformation("Contraseña cambiada con 2FA para usuario {UserId}", userId);
            return new ChangePasswordResponse(true, "Contraseña cambiada exitosamente");
        }

        public async Task<ChangePasswordResponse> VerifyAndConsumePasswordOtpAsync(Guid userId, string otpCode)
        {
            var otpHash = _tokens.Hash(otpCode);
            var token = await _context.SecurityTokens
                .FirstOrDefaultAsync(t =>
                    t.UserId == userId &&
                    t.TokenType == "PasswordChange2FA" &&
                    t.TokenHash == otpHash &&
                    !t.IsUsed &&
                    t.ExpiresAt > DateTime.Now);

            if (token is null)
            {
                _logger.LogWarning("OTP inválido o expirado para usuario {UserId}", userId);
                return new ChangePasswordResponse(false, "El código OTP es inválido o ha expirado");
            }

            token.IsUsed = true;
            await _context.SaveChangesAsync();
            return new ChangePasswordResponse(true, "OTP verificado");
        }

        // ── Helpers ────────────────────────────────────────────────────────────

        private async Task ApplyPasswordChangeAsync(Guid userId, LocalUserCredential cred, string newPassword)
        {
            var newHash = PasswordHasher.Hash(newPassword);
            var now = DateTime.Now;

            cred.PasswordHash = newHash;
            cred.PasswordCreatedAt = now;
            cred.MustChangePassword = false;
            cred.PasswordExpiresAt = now.AddDays(90);
            cred.FailedAttempts = 0;
            cred.IsLocked = false;

            await _users.UpdateLocalCredAsync(cred);

            _context.PasswordHistory.Add(new PasswordHistory
            {
                UserId = userId,
                PasswordHash = newHash,
                CreatedAt = now
            });
            await _context.SaveChangesAsync();
        }

        private static string GenerateOtp()
        {
            // Genera 6 dígitos criptográficamente seguros
            var bytes = new byte[4];
            RandomNumberGenerator.Fill(bytes);
            var value = Math.Abs(BitConverter.ToInt32(bytes, 0)) % 1_000_000;
            return value.ToString("D6");
        }

        private static bool IsPasswordComplex(string password) =>
            password.Length >= 8 &&
            password.Any(char.IsUpper) &&
            password.Any(char.IsDigit);

        private async Task<string[]> GetAdGroupsAsync(string email)
        {
            try
            {
                ;
                var dir = _identityResolver.GetDirectory("LocalAd");
                var adUser = await dir.GetUserByEmailAsync(email);
                _logger.LogInformation("[AD-GROUPS] Usuario {Email} no encontrado en AD local, se omiten grupos - adUser {adUser}", email, adUser);
                if (adUser is null)
                {
                    _logger.LogInformation("[AD-GROUPS] Usuario {Email} no encontrado en AD local, se omiten grupos", email);
                    return [];
                }
                var groups = await dir.GetUserGroupsAsync(adUser.Id);
                var names = groups.Select(g => g.Name).ToArray();
                _logger.LogInformation("[AD-GROUPS] {Count} grupos obtenidos del AD para {Email}: {Groups}",
                    names.Length, email, string.Join(", ", names));
                return names;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[AD-GROUPS] Error al consultar AD para {Email}, se continúa sin grupos", email);
                return [];
            }
        }
    }
}
