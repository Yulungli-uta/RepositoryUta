using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace WsSeguUta.AuthSystem.API.Security
{
    /// <summary>
    /// Carga el par de claves RSA usado para firmar (RS256) los JWT emitidos por el centralizador.
    /// La clave privada nunca se expone fuera de este proveedor; solo la pública se publica via JWKS.
    /// </summary>
    public sealed class RsaKeyProvider
    {
        public RsaSecurityKey SigningKey { get; }
        public RsaSecurityKey PublicKey { get; }
        public string KeyId { get; }

        public RsaKeyProvider(IConfiguration cfg, IWebHostEnvironment env, ILogger<RsaKeyProvider> logger)
        {
            var rsa = RSA.Create(2048);

            var privateKeyPath = cfg["Jwt:PrivateKeyPath"];
            var privateKeyPem = cfg["Jwt:PrivateKeyPem"];

            if (!string.IsNullOrWhiteSpace(privateKeyPem))
            {
                rsa.ImportFromPem(privateKeyPem);
            }
            else if (!string.IsNullOrWhiteSpace(privateKeyPath) && File.Exists(privateKeyPath))
            {
                rsa.ImportFromPem(File.ReadAllText(privateKeyPath));
            }
            else if (env.IsDevelopment())
            {
                // Solo en Development: generar una clave efímera para no bloquear el flujo local.
                // En Production esto es un error de configuración explícito.
                logger.LogWarning(
                    "Jwt:PrivateKeyPath/PrivateKeyPem no configurados. Generando clave RSA efímera SOLO para Development. " +
                    "Los tokens no serán válidos tras reiniciar el proceso.");
            }
            else
            {
                throw new InvalidOperationException(
                    "Jwt:PrivateKeyPath o Jwt:PrivateKeyPem deben estar configurados en Production.");
            }

            KeyId = cfg["Jwt:KeyId"] ?? "wssegu-uta-key-1";

            SigningKey = new RsaSecurityKey(rsa) { KeyId = KeyId };
            PublicKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false)) { KeyId = KeyId };
        }
    }
}
