namespace WsSeguUta.AuthSystem.API.Utilities
{
    /// <summary>Datos del cliente de una petición HTTP (IP y navegador), en un solo lugar.</summary>
    public static class ClientRequestInfo
    {
        public static string? GetClientIp(HttpContext context)
        {
            // Si está detrás de proxy / gateway, esto suele venir poblado
            var xff = context.Request.Headers["X-Forwarded-For"].ToString();
            if (!string.IsNullOrWhiteSpace(xff))
                return xff.Split(',')[0].Trim();

            var xRealIp = context.Request.Headers["X-Real-IP"].ToString();
            if (!string.IsNullOrWhiteSpace(xRealIp))
                return xRealIp.Trim();

            var ip = context.Connection.RemoteIpAddress?.ToString();

            // Normaliza loopback IPv6 a 127.0.0.1 (útil en dev)
            if (ip == "::1") return "127.0.0.1";

            return ip;
        }

        public static string? GetUserAgent(HttpContext context)
            => context.Request.Headers["User-Agent"].ToString();
    }
}
