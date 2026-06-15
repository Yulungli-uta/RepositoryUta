using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public class ClientApplicationService : IClientApplicationService
{
    private readonly IApplicationRepository _repo;

    public ClientApplicationService(IApplicationRepository repo) => _repo = repo;

    public Task<bool> IsClientApplicationAllowedAsync(string? clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
            return Task.FromResult(false);

        return _repo.ExistsActiveClientAsync(clientId.Trim());
    }
}
