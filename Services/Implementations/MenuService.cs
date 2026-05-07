using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class MenuService : IMenuService
    {
        private readonly IMenuRepository _repo;

        public MenuService(IMenuRepository repo) => _repo = repo;

        public Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId) =>
            _repo.GetMenuByUserAsync(userId);
    }
}
