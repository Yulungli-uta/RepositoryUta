namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    /// <summary>Códigos de eventos de seguimiento que se guardan en auth.tbl_UserActivityLog.</summary>
    public static class UserActivityCodes
    {
        public const string MenuLoadEmpty = "MENU_LOAD_EMPTY";
        public const string MenuLoadError = "MENU_LOAD_ERROR";
        public const string RefreshRejected = "REFRESH_REJECTED";
        public const string SessionResetAuto = "SESSION_RESET_AUTO";
        public const string LoginNotificationNoListener = "LOGIN_NOTIFICATION_NO_LISTENER";

        /// <summary>Motivos que el cliente puede enviar al cerrar sesión (lista cerrada).</summary>
        public static readonly IReadOnlySet<string> AllowedLogoutReasons =
            new HashSet<string>(StringComparer.Ordinal) { "PERMISSIONS_RECOVERY" };
    }

    /// <summary>
    /// Bitácora de eventos de acceso por usuario (auth.tbl_UserActivityLog). Solo anomalías:
    /// la actividad normal (logins, renovaciones, cierres) ya queda en LoginHistory y UserSessions.
    /// </summary>
    public interface IUserActivityService
    {
        /// <summary>Registra un evento. Best-effort: nunca lanza ni altera la respuesta del llamador.</summary>
        Task LogAsync(Guid userId, string activity, object? details = null, Guid? sessionId = null,
            string? ipAddress = null, string? userAgent = null);
    }
}
