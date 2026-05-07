namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    /// <summary>Resuelve el proveedor correcto dado un nombre de proveedor.</summary>
    public interface IIdentityProviderResolver
    {
        IIdentityProvider GetProvider(string providerName);
        IDirectoryService GetDirectory(string providerName);
        IReadOnlyList<string> RegisteredProviders { get; }
    }
}
