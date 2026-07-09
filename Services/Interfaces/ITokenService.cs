namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ITokenService
    {
        string Create(Guid userId, string email, IEnumerable<string> roles, int? hrEmployeeId = null);
        string Create(Guid userId, string email, IEnumerable<string> roles, IEnumerable<string> adGroups, int? hrEmployeeId = null);
        string Hash(string input);
    }
}
