using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WsSeguUta.AuthSystem.API.Security;

namespace WsSeguUta.AuthSystem.API.Controllers
{
    /// <summary>
    /// Endpoints de descubrimiento estándar (RFC 7517 / OIDC discovery).
    /// Publica únicamente la clave pública usada para verificar la firma de los JWT emitidos.
    /// No depende de servicios de sesión/login: su único propósito es publicar metadata criptográfica.
    /// </summary>
    [ApiController]
    public class WellKnownController : ControllerBase
    {
        private readonly RsaKeyProvider _keys;

        public WellKnownController(RsaKeyProvider keys)
        {
            _keys = keys;
        }

        [HttpGet("/.well-known/jwks.json")]
        [AllowAnonymous]
        [ResponseCache(Duration = 3600)]
        public IActionResult GetJwks()
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(_keys.PublicKey);
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.RsaSha256;
            jwk.Kid = _keys.KeyId;

            return Ok(new { keys = new[] { jwk } });
        }
    }
}
