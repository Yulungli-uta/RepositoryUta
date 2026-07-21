using System.Security.Cryptography;
using System.Text;
using WsSeguUta.AuthSystem.API.Security;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class TokenService : ITokenService
    {
        private readonly JwtTokenService _jwt;

        public TokenService(JwtTokenService jwt) => _jwt = jwt;

        public Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, int? hrEmployeeId = null, TimeSpan? lifetime = null, CancellationToken ct = default) =>
            _jwt.CreateAsync(userId, email, roles, [], lifetime, hrEmployeeId, ct);

        public Task<string> CreateAsync(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups, int? hrEmployeeId = null, TimeSpan? lifetime = null, CancellationToken ct = default) =>
            _jwt.CreateAsync(userId, email, roles, adGroups, lifetime, hrEmployeeId, ct);

        public string Hash(string input) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }
}
