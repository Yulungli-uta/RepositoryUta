namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ITokenService
    {
        Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, int? hrEmployeeId = null, TimeSpan? lifetime = null, CancellationToken ct = default);
        Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups, int? hrEmployeeId = null, TimeSpan? lifetime = null, CancellationToken ct = default);
        string Hash(string input);
    }
}
