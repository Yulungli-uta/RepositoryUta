using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace WsSeguUta.AuthSystem.API.Utilities
{
  public static class PasswordHasher
  {
    public static string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password);
    public static bool Verify(string password,string hash){
      //Console.WriteLine($"Verifying password PasswordHasher-Verify - for hash: {hash}, password: {password}");
      if (hash.StartsWith("$2")) { 
                Console.WriteLine($"pass word hasheado BCrypt.Net.BCrypt.{BCrypt.Net.BCrypt.HashPassword(password)}");
                return BCrypt.Net.BCrypt.Verify(password, hash); 
        }
      if (hash.Length==64 && Regex.IsMatch(hash,"^[0-9A-Fa-f]{64}$")){
        using var sha = SHA256.Create(); var hex = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
        //Console.WriteLine($"valor sha: {sha}, Valor hex {hex}, valor hash: {hash}");
        return string.Equals(hex, hash, StringComparison.OrdinalIgnoreCase);
      }
      return false;
    }
  }
}
