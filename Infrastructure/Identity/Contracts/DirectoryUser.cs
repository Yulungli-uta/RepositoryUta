namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    public sealed record DirectoryUser(
        string Id,
        string Email,
        string DisplayName,
        string? GivenName,
        string? Surname,
        string? JobTitle,
        string? Department,
        bool AccountEnabled,
        DateTimeOffset? CreatedDateTime);
}
