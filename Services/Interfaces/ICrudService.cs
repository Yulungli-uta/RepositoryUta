using System.Linq.Expressions;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    public interface ICrudService<TEntity, TCreate, TUpdate> where TEntity : class
    {
        Task<PagedResult<TEntity>> ListAsync(int page, int pageSize, CancellationToken ct = default);

        /// <summary>Listado paginado con filtro dinámico (búsqueda por texto) y orden opcional.</summary>
        Task<PagedResult<TEntity>> ListAsync(
            Expression<Func<TEntity, bool>>? predicate,
            int page,
            int pageSize,
            CancellationToken ct = default,
            Expression<Func<TEntity, object>>? orderBy = null,
            bool ascending = true);
        Task<TEntity?> GetAsync(params object[] key);
        Task<TEntity> CreateAsync(TCreate dto);
        Task<TEntity?> UpdateAsync(object key, TUpdate dto);
        Task<bool> DeleteAsync(params object[] key);
    }
}
