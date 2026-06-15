namespace WsSeguUta.AuthSystem.API.Data.Repositories;

public interface IApplicationRepository
{
    Task<bool> ExistsActiveClientAsync(string clientId);
}
