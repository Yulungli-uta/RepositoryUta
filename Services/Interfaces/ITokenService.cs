namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ITokenService
    {
        string Create(Guid userId, string email, IEnumerable<string> roles);
        string Hash(string input);
    }
}
