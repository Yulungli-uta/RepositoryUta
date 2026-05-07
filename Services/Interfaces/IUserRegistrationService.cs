using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface IUserRegistrationService
    {
        Task<object> CreateUserWithEmployeeAsync(CreateUserDto dto);
    }
}
