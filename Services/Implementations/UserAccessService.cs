using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class UserAccessService : IUserAccessService
    {
        private const int MaxRangeDays = 31;
        private const int MaxPerSource = 2000;
        private const int MaxPageSize = 200;

        private readonly AuthDbContext _db;
        private readonly IAppClock _clock;

        public UserAccessService(AuthDbContext db, IAppClock clock)
        {
            _db = db;
            _clock = clock;
        }

        public async Task<UserAccessTimelineDto?> GetTimelineAsync(Guid userId, DateTime from, DateTime to, int page, int pageSize, CancellationToken ct)
        {
            var user = await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user is null) return null;

            if (to < from) (from, to) = (to, from);
            if ((to - from).TotalDays > MaxRangeDays) from = to.AddDays(-MaxRangeDays);
            page = Math.Max(page, 1);
            pageSize = Math.Clamp(pageSize, 1, MaxPageSize);

            var events = new List<UserAccessEventDto>();
            events.AddRange(await LoadLoginEventsAsync(userId, from, to, ct));
            events.AddRange(await LoadSessionEventsAsync(userId, from, to, ct));
            events.AddRange(await LoadActivityEventsAsync(userId, from, to, ct));

            var ordered = events.OrderByDescending(e => e.Timestamp).ToList();
            var total = ordered.Count;
            var items = ordered.Skip((page - 1) * pageSize).Take(pageSize).ToList();
            var totalPages = (int)Math.Ceiling(total / (double)pageSize);

            return new UserAccessTimelineDto(await BuildSummaryAsync(user, ct), items, page, pageSize, total, totalPages);
        }

        // ── Resumen ────────────────────────────────────────────────────────────

        private async Task<UserAccessSummaryDto> BuildSummaryAsync(Models.Entities.User user, CancellationToken ct)
        {
            var now = _clock.Now;

            var roles = await (
                from ur in _db.UserRoles
                join r in _db.Roles on ur.RoleId equals r.Id
                where ur.UserId == user.Id && !ur.IsDeleted && !r.IsDeleted
                      && (ur.ExpiresAt == null || ur.ExpiresAt > now)
                select r.Name).ToArrayAsync(ct);

            var hrEmployeeId = await _db.UserEmployees.AsNoTracking()
                .Where(e => e.UserId == user.Id && e.IsActive)
                .Select(e => e.HrEmployeeId)
                .FirstOrDefaultAsync(ct);

            var lastMicrosoftLogin = await _db.LoginHistory.AsNoTracking()
                .Where(l => l.UserId == user.Id && l.LoginType == "AzureAD" && l.LoginStatus == "Success")
                .MaxAsync(l => (DateTime?)l.LoginDateTime, ct);

            // LastActivityAt nunca se llena: el último acceso real es la sesión más reciente (inicio o renovación)
            var lastAppAccess = await _db.UserSessions.AsNoTracking()
                .Where(s => s.UserId == user.Id)
                .MaxAsync(s => (DateTime?)s.CreatedAt, ct);

            var validSessions = await _db.UserSessions.AsNoTracking()
                .CountAsync(s => s.UserId == user.Id && s.IsActive && s.ExpiresAt > now, ct);

            // Cuenta Local bloqueada: el bloqueo se mantiene hasta que un administrador lo desbloquea
            var credential = await _db.LocalUserCredentials.AsNoTracking()
                .Where(c => c.UserId == user.Id)
                .Select(c => new { c.IsLocked, c.LockedUntil })
                .FirstOrDefaultAsync(ct);
            var accountLocked = credential is not null
                && (credential.IsLocked || (credential.LockedUntil.HasValue && credential.LockedUntil.Value > now));

            return new UserAccessSummaryDto(user.Id, user.Email, user.DisplayName, user.UserType, user.IsActive,
                hrEmployeeId, roles, lastMicrosoftLogin, lastAppAccess, validSessions,
                accountLocked, accountLocked ? credential!.LockedUntil : null);
        }

        // ── Fuentes de eventos ─────────────────────────────────────────────────

        private async Task<List<UserAccessEventDto>> LoadLoginEventsAsync(Guid userId, DateTime from, DateTime to, CancellationToken ct)
        {
            var rows = await _db.LoginHistory.AsNoTracking()
                .Where(l => l.UserId == userId && l.LoginDateTime >= from && l.LoginDateTime <= to)
                .OrderByDescending(l => l.LoginDateTime)
                .Take(MaxPerSource)
                .Select(l => new { l.LoginDateTime, l.LoginType, l.LoginStatus, l.FailureReason, l.IpAddress, l.DeviceInfo, l.UserAgent, l.SessionId })
                .ToListAsync(ct);

            return rows.Select(l =>
            {
                var device = DescribeDevice(l.DeviceInfo, l.UserAgent);
                if (l.LoginType == "Refresh")
                    return new UserAccessEventDto(l.LoginDateTime, "SECURITY", "Reutilización de un token ya renovado", l.FailureReason, l.IpAddress, device, l.SessionId);
                if (l.LoginStatus == "Success")
                    return new UserAccessEventDto(l.LoginDateTime, "LOGIN",
                        l.LoginType == "AzureAD" ? "Inicio de sesión con Microsoft" : "Inicio de sesión local",
                        null, l.IpAddress, device, l.SessionId);
                var detail = string.IsNullOrWhiteSpace(l.FailureReason) ? l.LoginStatus : $"{l.LoginStatus}: {l.FailureReason}";
                return new UserAccessEventDto(l.LoginDateTime, "LOGIN_FAILED", "Intento de inicio de sesión fallido", detail, l.IpAddress, device, l.SessionId);
            }).ToList();
        }

        private async Task<List<UserAccessEventDto>> LoadSessionEventsAsync(Guid userId, DateTime from, DateTime to, CancellationToken ct)
        {
            // Se proyectan solo las columnas necesarias: la fila de sesión trae el access token completo
            var rows = await _db.UserSessions.AsNoTracking()
                .Where(s => s.UserId == userId
                    && ((s.RevokedAt != null && s.RevokedAt >= from && s.RevokedAt <= to)
                        || (s.Status == "Expired" && s.ExpiresAt >= from && s.ExpiresAt <= to)))
                .Take(MaxPerSource)
                .Select(s => new { s.SessionId, s.Status, s.RevokedAt, s.RevokedBy, s.ExpiresAt, s.IpAddress, s.DeviceInfo, s.UserAgent })
                .ToListAsync(ct);

            var list = new List<UserAccessEventDto>();
            foreach (var s in rows)
            {
                var device = DescribeDevice(s.DeviceInfo, s.UserAgent);
                switch (s.Status)
                {
                    case "Rotated":
                        list.Add(new UserAccessEventDto(s.RevokedAt!.Value, "SESSION_RENEWED", "Sesión renovada",
                            "El usuario seguía conectado; no inició sesión de nuevo", s.IpAddress, device, s.SessionId));
                        break;
                    case "Logout":
                        list.Add(new UserAccessEventDto(s.RevokedAt!.Value, "LOGOUT", "Cierre de sesión", null, s.IpAddress, device, s.SessionId));
                        break;
                    case "Superseded":
                        list.Add(new UserAccessEventDto(s.RevokedAt ?? s.ExpiresAt, "SESSION_REVOKED", "Sesión reemplazada",
                            "Se cerró porque el usuario inició sesión de nuevo en el mismo navegador", s.IpAddress, device, s.SessionId));
                        break;
                    case "Expired":
                        list.Add(new UserAccessEventDto(s.ExpiresAt, "SESSION_EXPIRED", "Sesión vencida", "Venció sin que el usuario cerrara sesión", s.IpAddress, device, s.SessionId));
                        break;
                    default:
                        if (s.RevokedAt is not null)
                            list.Add(new UserAccessEventDto(s.RevokedAt.Value, "SESSION_REVOKED", "Sesión revocada",
                                string.IsNullOrWhiteSpace(s.RevokedBy) ? s.Status : $"{s.Status} por {s.RevokedBy}", s.IpAddress, device, s.SessionId));
                        break;
                }
            }
            return list;
        }

        private async Task<List<UserAccessEventDto>> LoadActivityEventsAsync(Guid userId, DateTime from, DateTime to, CancellationToken ct)
        {
            var rows = await _db.UserActivityLogs.AsNoTracking()
                .Where(a => a.UserId == userId && a.Timestamp >= from && a.Timestamp <= to)
                .OrderByDescending(a => a.Timestamp)
                .Take(MaxPerSource)
                .ToListAsync(ct);

            return rows.Select(a => new UserAccessEventDto(a.Timestamp, "ACTIVITY", ActivityTitle(a.Activity),
                a.ActivityDetails, a.IpAddress, DescribeDevice(null, a.UserAgent), a.SessionId)).ToList();
        }

        private static string ActivityTitle(string activity) => activity switch
        {
            UserActivityCodes.MenuLoadEmpty => "El menú del usuario salió vacío a pesar de tener roles",
            UserActivityCodes.MenuLoadError => "Error del servidor al cargar el menú",
            UserActivityCodes.RefreshRejected => "Renovación de sesión rechazada",
            UserActivityCodes.SessionResetAuto => "Sesión cerrada automáticamente para renovar el acceso",
            UserActivityCodes.LoginNotificationNoListener => "El inicio de sesión con Microsoft terminó pero la pestaña del usuario no estaba conectada para recibirlo",
            _ => activity
        };

        // ── Dispositivo legible ("Chrome · Android") ───────────────────────────

        private static string? DescribeDevice(string? deviceInfo, string? userAgent)
        {
            var ua = userAgent ?? string.Empty;
            var browser = ua.Contains("Edg/") ? "Edge"
                : ua.Contains("Firefox/") ? "Firefox"
                : ua.Contains("Chrome/") ? "Chrome"
                : ua.Contains("Safari/") ? "Safari"
                : null;
            var os = ua.Contains("Android") ? "Android"
                : ua.Contains("iPhone") || ua.Contains("iPad") ? "iOS"
                : ua.Contains("Windows") ? "Windows"
                : ua.Contains("Mac OS") ? "macOS"
                : ua.Contains("Linux") ? "Linux"
                : null;

            if (browser is null && os is null) return string.IsNullOrWhiteSpace(deviceInfo) ? null : deviceInfo;
            return browser is not null && os is not null ? $"{browser} · {os}" : browser ?? os;
        }
    }
}
