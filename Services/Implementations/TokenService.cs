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

        public string Create(Guid userId, string email, IEnumerable<string> roles) =>
            _jwt.Create(userId, email, roles);

        public string Create(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups) =>
            _jwt.Create(userId, email, roles, adGroups);

        public string Hash(string input) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }
}
