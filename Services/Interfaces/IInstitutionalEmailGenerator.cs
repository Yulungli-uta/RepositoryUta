namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

public interface IInstitutionalEmailGenerator
{
    Task<string> GenerateAvailableEmailAsync(
        int hrEmployeeId,
        string givenName,
        string surname,
        CancellationToken ct = default);
}
