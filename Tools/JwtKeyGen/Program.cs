using System.Security.Cryptography;

// Genera el par de claves RSA (PKCS8 / SubjectPublicKeyInfo) que RsaKeyProvider carga via
// Jwt:PrivateKeyPath. Existe porque Windows PowerShell 5.1 (.NET Framework) no expone
// RSA.ExportPkcs8PrivateKeyPem/ExportSubjectPublicKeyInfoPem; este ejecutable, al publicarse
// self-contained, no depende de que el servidor tenga SDK, pwsh ni openssl instalados.

if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
{
    Console.WriteLine("Uso: JwtKeyGen <carpeta-destino> [--force]");
    return 1;
}

var outputDir = args[0];
var force = args.Contains("--force");

var privatePath = Path.Combine(outputDir, "jwt-private.pem");
var publicPath = Path.Combine(outputDir, "jwt-public.pem");

if (!force && (File.Exists(privatePath) || File.Exists(publicPath)))
{
    Console.Error.WriteLine(
        $"ERROR: ya existen claves en '{outputDir}'. Sobrescribirlas invalida TODOS los tokens JWT " +
        "emitidos y activos (los usuarios con sesion abierta deberan volver a iniciar sesion). " +
        "Vuelve a ejecutar con --force si esto es intencional.");
    return 1;
}

Directory.CreateDirectory(outputDir);

using var rsa = RSA.Create(2048);
File.WriteAllText(privatePath, rsa.ExportPkcs8PrivateKeyPem());
File.WriteAllText(publicPath, rsa.ExportSubjectPublicKeyInfoPem());

Console.WriteLine($"Claves RSA generadas en: {outputDir}");
Console.WriteLine($"  {privatePath}");
Console.WriteLine($"  {publicPath}");
Console.WriteLine();
Console.WriteLine("Siguiente paso: restringir permisos del archivo privado con icacls y reciclar el App Pool.");
return 0;
