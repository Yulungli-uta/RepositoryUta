namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IMenuService
    {
        Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId);
    }
}
