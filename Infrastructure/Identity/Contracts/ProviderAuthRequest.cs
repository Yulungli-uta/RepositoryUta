namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    public sealed record ProviderAuthRequest(
        string Provider,
        string Username,
        string Password,
        string? IpAddress = null,
        string? UserAgent = null,
        string? DeviceInfo = null);
}
