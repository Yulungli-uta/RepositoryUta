using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace WsSeguUta.AuthSystem.API.Security
{
    public sealed class JwtTokenService
    {
        private readonly RsaKeyProvider _keys;
        private readonly string _issuer;
        private readonly string _audience;

        public JwtTokenService(IConfiguration cfg, RsaKeyProvider keys)
        {
            _keys = keys;
            _issuer = cfg["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
            _audience = cfg["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";
        }

        public string Create(Guid userId, string email, IEnumerable<string> roles, TimeSpan? lifetime = null, int? hrEmployeeId = null)
            => Create(userId, email, roles, [], lifetime, hrEmployeeId);

        public string Create(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups, TimeSpan? lifetime = null, int? hrEmployeeId = null)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new(JwtRegisteredClaimNames.Email, email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(ClaimTypes.NameIdentifier, userId.ToString()),
                new(ClaimTypes.Name, email)
            };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
            claims.AddRange(adGroups.Select(g => new Claim("ad_group", g)));
            if (hrEmployeeId.HasValue)
                claims.Add(new Claim("employeeId", hrEmployeeId.Value.ToString()));

            var token = new JwtSecurityToken(
                _issuer,
                _audience,
                claims,
                expires: DateTime.Now.Add(lifetime ?? TimeSpan.FromHours(8)),
                signingCredentials: new SigningCredentials(_keys.SigningKey, SecurityAlgorithms.RsaSha256));

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
