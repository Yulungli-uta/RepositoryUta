using Microsoft.EntityFrameworkCore;

namespace WsSeguUta.AuthSystem.API.Data.Repositories;

public class ApplicationRepository : IApplicationRepository
{
    private readonly AuthDbContext _context;

    public ApplicationRepository(AuthDbContext context) => _context = context;

    public Task<bool> ExistsActiveClientAsync(string clientId) =>
        _context.Applications
            .AsNoTracking()
            .AnyAsync(app => app.ClientId == clientId && app.IsActive && !app.IsDeleted);
}
