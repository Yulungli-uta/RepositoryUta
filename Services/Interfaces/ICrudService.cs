using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ICrudService<TEntity, TCreate, TUpdate> where TEntity : class
    {
        Task<PagedResult<TEntity>> ListAsync(int page, int pageSize, CancellationToken ct = default);
        Task<TEntity?> GetAsync(params object[] key);
        Task<TEntity> CreateAsync(TCreate dto);
        Task<TEntity?> UpdateAsync(object key, TUpdate dto);
        Task<bool> DeleteAsync(params object[] key);
    }
}
