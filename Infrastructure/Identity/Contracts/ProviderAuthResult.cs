namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    public sealed record ProviderAuthResult(
        bool Success,
        string? Email,
        string? DisplayName,
        string? FailureReason = null,
        IReadOnlyDictionary<string, string>? Claims = null);
}
