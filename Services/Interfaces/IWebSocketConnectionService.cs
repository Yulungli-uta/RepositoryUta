namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IWebSocketConnectionService
    {
        Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null, string? browserId = null);
        Task UnregisterConnectionAsync(string connectionId);
        Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId);
        Task<bool> IsConnectionActiveAsync(string connectionId);
        Task UpdateLastPingAsync(string connectionId);
        Task<int> GetActiveConnectionCountAsync(string clientId);

        /// <summary>true si hay una conexión activa de ese navegador (browserId). Ante un error responde true para no generar falsas alarmas.</summary>
        Task<bool> HasActiveBrowserConnectionAsync(string browserId);
        Task CleanupInactiveConnectionsAsync(int inactiveMinutes = 60);
    }
}
