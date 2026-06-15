namespace WsSeguUta.AuthSystem.API.Services.Interfaces;

public interface IClientApplicationService
{
    Task<bool> IsClientApplicationAllowedAsync(string? clientId);
}
