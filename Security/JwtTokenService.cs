using System.IdentityModel.Tokens.Jwt; using System.Security.Claims; using System.Text; using Microsoft.IdentityModel.Tokens;
namespace WsSeguUta.AuthSystem.API.Security
{
  public class JwtTokenService
  {
    private readonly IConfiguration _cfg; public JwtTokenService(IConfiguration cfg)=>_cfg=cfg;
    public string Create(Guid userId,string email,IEnumerable<string> roles,TimeSpan? lifetime=null){
      var key=_cfg["Jwt:Key"]??"dev"; 
            var issuer=_cfg["Jwt:Issuer"]??"WsSeguUta.AuthSystem.API"; 
            var aud=_cfg["Jwt:Audience"]??"WsSeguUta.AuthSystem.API";
      var claims=new List<Claim>{ new(ClaimTypes.NameIdentifier,userId.ToString()), new(ClaimTypes.Name,email) }; claims.AddRange(roles.Select(r=>new Claim(ClaimTypes.Role,r)));
      var creds=new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),SecurityAlgorithms.HmacSha256);
      var token=new JwtSecurityToken(issuer,aud,claims,expires:DateTime.Now.Add(lifetime??TimeSpan.FromHours(8)),signingCredentials:creds);
      return new JwtSecurityTokenHandler().WriteToken(token);
    }
  }
}
