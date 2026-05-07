using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WsSeguUta.AuthSystem.API.Security
{
    public sealed class JwtTokenService
    {
        private readonly SymmetricSecurityKey _signingKey;
        private readonly string _issuer;
        private readonly string _audience;

        public JwtTokenService(IConfiguration cfg)
        {
            var key = cfg["Jwt:Key"]
                ?? throw new InvalidOperationException("Jwt:Key no está configurada.");
            _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            _issuer = cfg["Jwt:Issuer"] ?? "WsSeguUta.AuthSystem.API";
            _audience = cfg["Jwt:Audience"] ?? "WsSeguUta.AuthSystem.API";
        }

        public string Create(Guid userId, string email, IEnumerable<string> roles, TimeSpan? lifetime = null)
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

            var token = new JwtSecurityToken(
                _issuer,
                _audience,
                claims,
                expires: DateTime.Now.Add(lifetime ?? TimeSpan.FromHours(8)),
                signingCredentials: new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256));

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
