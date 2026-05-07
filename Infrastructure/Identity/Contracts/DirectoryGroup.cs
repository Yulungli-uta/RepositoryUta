namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    public sealed record DirectoryGroup(
        string Id,
        string Name,
        string? Description,
        string? Email);
}
