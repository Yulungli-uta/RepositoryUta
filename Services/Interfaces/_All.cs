using System.Linq.Expressions;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
  public interface IAuthService { Task<TokenPair?> LoginLocalAsync(string email,string password); Task<TokenPair?> RefreshAsync(string refreshToken); Task<bool> LogoutAsync(string refreshToken); Task<object?> MeAsync(Guid userId); }
  public interface ITokenService { string Create(Guid userId,string email,IEnumerable<string> roles); string Hash(string input); }
  public interface IAzureAuthService { Task<(string Url,string State)> BuildAuthUrlAsync(); Task<TokenPair?> HandleCallbackAsync(string code,string state); }
  public interface IMenuService { Task<IEnumerable<object>> GetMenuForUserAsync(Guid userId); }

  // CRUD genÃ©rico para todas las entidades
  public interface ICrudService<TEntity, TCreate, TUpdate> where TEntity: class
  {
    Task<IEnumerable<TEntity>> ListAsync(int page,int size);
    Task<TEntity?> GetAsync(params object[] key);
    Task<TEntity> CreateAsync(TCreate dto);
    Task<TEntity?> UpdateAsync(object key, TUpdate dto);
    Task<bool> DeleteAsync(params object[] key);
  }
}
