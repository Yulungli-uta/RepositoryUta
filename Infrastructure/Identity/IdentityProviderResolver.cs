using WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity
{
    public sealed class IdentityProviderResolver : IIdentityProviderResolver
    {
        private readonly IReadOnlyDictionary<string, IIdentityProvider> _providers;
        private readonly IReadOnlyDictionary<string, IDirectoryService> _directories;

        public IdentityProviderResolver(
            IEnumerable<IIdentityProvider> providers,
            IEnumerable<IDirectoryService> directories)
        {
            _providers = providers.ToDictionary(p => p.ProviderName, StringComparer.OrdinalIgnoreCase);
            _directories = directories.ToDictionary(d => d.ProviderName, StringComparer.OrdinalIgnoreCase);
        }

        public IReadOnlyList<string> RegisteredProviders => _providers.Keys.ToList();

        public IIdentityProvider GetProvider(string providerName)
        {
            if (_providers.TryGetValue(providerName, out var provider)) return provider;
            throw new NotSupportedException($"Proveedor de identidad '{providerName}' no está registrado. Disponibles: {string.Join(", ", _providers.Keys)}");
        }

        public IDirectoryService GetDirectory(string providerName)
        {
            if (_directories.TryGetValue(providerName, out var directory)) return directory;
            throw new NotSupportedException($"Servicio de directorio '{providerName}' no está registrado. Disponibles: {string.Join(", ", _directories.Keys)}");
        }
    }
}
