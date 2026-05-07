namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    /// <summary>Valida credenciales contra un proveedor de identidad (Entra ID, AD local, local DB).</summary>
    public interface IIdentityProvider
    {
        string ProviderName { get; }
        Task<ProviderAuthResult> AuthenticateAsync(ProviderAuthRequest request, CancellationToken ct = default);
    }
}
