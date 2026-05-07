using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class UserRegistrationService : IUserRegistrationService
    {
        private readonly AuthDbContext _context;
        private readonly ILogger<UserRegistrationService> _logger;

        public UserRegistrationService(AuthDbContext context, ILogger<UserRegistrationService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<object> CreateUserWithEmployeeAsync(CreateUserDto dto)
        {
            await using var tx = await _context.Database.BeginTransactionAsync();

            try
            {
                var email = dto.Email.Trim();

                var userExists = await _context.Users.AnyAsync(u => u.Email == email);
                if (userExists)
                    throw new InvalidOperationException("Ya existe un usuario con ese email.");

                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Email = email,
                    DisplayName = dto.DisplayName,
                    UserType = dto.UserType,
                    IsActive = true,
                    CreatedAt = DateTime.Now
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                var userEmployeeExists = await _context.Set<UserEmployee>()
                    .AnyAsync(ue => ue.EmployeeEmail == email);

                if (userEmployeeExists)
                    throw new InvalidOperationException("Ya existe un UserEmployee con ese email.");

                var userEmployee = new UserEmployee
                {
                    UserId = user.Id,
                    EmployeeEmail = email,
                    IsActive = true,
                    SyncDate = DateTime.Now,
                    Notes = "Creado manualmente desde el panel de administración"
                };

                _context.Set<UserEmployee>().Add(userEmployee);
                await _context.SaveChangesAsync();

                await tx.CommitAsync();
                _logger.LogInformation("Usuario {UserId} creado correctamente con email {Email}", user.Id, email);

                return new { User = user, UserEmployee = userEmployee };
            }
            catch
            {
                await tx.RollbackAsync();
                throw;
            }
        }
    }
}
