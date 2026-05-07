namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IWebSocketConnectionService
    {
        Task RegisterConnectionAsync(string connectionId, string clientId, string? userId = null);
        Task UnregisterConnectionAsync(string connectionId);
        Task<IEnumerable<string>> GetActiveConnectionsForApplicationAsync(string clientId);
        Task<bool> IsConnectionActiveAsync(string connectionId);
        Task UpdateLastPingAsync(string connectionId);
        Task<int> GetActiveConnectionCountAsync(string clientId);
        Task CleanupInactiveConnectionsAsync(int inactiveMinutes = 60);
    }
}
