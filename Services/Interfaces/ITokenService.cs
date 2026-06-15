namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ITokenService
    {
        string Create(Guid userId, string email, IEnumerable<string> roles);
        string Create(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups);
        string Hash(string input);
    }
}
