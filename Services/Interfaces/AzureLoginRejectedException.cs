namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    /// <summary>Códigos genéricos que se muestran al usuario; el motivo exacto queda solo en el log y la auditoría.</summary>
    public static class AzureLoginFailureCodes
    {
        public const string Cancelled = "CANCELLED";
        public const string ExpiredAttempt = "EXPIRED_ATTEMPT";
        public const string NoAccess = "NO_ACCESS";
        public const string ServerError = "SERVER_ERROR";
    }

    /// <summary>
    /// Rechazo del login Azure con un código genérico para el usuario. Hereda de
    /// <see cref="UnauthorizedAccessException"/> para no cambiar quién la captura.
    /// </summary>
    public sealed class AzureLoginRejectedException : UnauthorizedAccessException
    {
        public string Code { get; }

        public AzureLoginRejectedException(string code, string message) : base(message) => Code = code;
    }
}
