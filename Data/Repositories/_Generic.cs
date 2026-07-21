using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;

namespace WsSeguUta.AuthSystem.API.Data.Repositories
{
    public interface IGenericRepository<T> where T : class
    {
        /// <summary>
        /// Retorna un resultado paginado con soporte de ordenamiento.
        /// Método preferido para todos los listados.
        /// </summary>
        Task<PagedResult<T>> GetPagedAsync(
            int page,
            int pageSize,
            CancellationToken ct = default,
            Expression<Func<T, object>>? orderBy = null,
            bool ascending = true);

        /// <summary>
        /// Retorna un resultado paginado con filtro dinámico y ordenamiento.
        /// Usar cuando se requiere búsqueda por texto u otros criterios.
        /// </summary>
        Task<PagedResult<T>> GetPagedAsync(
            Expression<Func<T, bool>>? predicate,
            int page,
            int pageSize,
            CancellationToken ct = default,
            Expression<Func<T, object>>? orderBy = null,
            bool ascending = true);

        Task<T?> GetAsync(params object[] key);
        Task<T> AddAsync(T entity);
        Task<T?> UpdateAsync(T entity);
        Task<bool> DeleteAsync(params object[] key);

        /// <summary>Expone el IQueryable subyacente para consultas avanzadas en repositorios especializados.</summary>
        IQueryable<T> Query();
    }

    public class GenericRepository<T> : IGenericRepository<T> where T : class
    {
        private readonly AuthDbContext _db;
        private readonly DbSet<T> _set;

        public GenericRepository(AuthDbContext db) { _db = db; _set = db.Set<T>(); }

        public async Task<PagedResult<T>> GetPagedAsync(
            int page,
            int pageSize,
            CancellationToken ct = default,
            Expression<Func<T, object>>? orderBy = null,
            bool ascending = true)
            => await GetPagedAsync(null, page, pageSize, ct, orderBy, ascending);

        public async Task<PagedResult<T>> GetPagedAsync(
            Expression<Func<T, bool>>? predicate,
            int page,
            int pageSize,
            CancellationToken ct = default,
            Expression<Func<T, object>>? orderBy = null,
            bool ascending = true)
        {
            if (page < 1) page = 1;
            if (pageSize < 1) pageSize = 20;
            if (pageSize > 200) pageSize = 200;

            IQueryable<T> q = _set.AsNoTracking();

            if (predicate != null)
                q = q.Where(predicate);

            if (orderBy != null)
                q = ascending ? q.OrderBy(orderBy) : q.OrderByDescending(orderBy);

            var totalCount = await q.LongCountAsync(ct);

            if (totalCount == 0)
                return PagedResult<T>.Empty(page, pageSize);

            var items = await q
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync(ct);

            return PagedResult<T>.Create(items, page, pageSize, totalCount);
        }

        public Task<T?> GetAsync(params object[] key) => _set.FindAsync(key).AsTask();

        public async Task<T> AddAsync(T entity) { _set.Add(entity); await _db.SaveChangesAsync(); return entity; }

        public async Task<T?> UpdateAsync(T entity) { _set.Update(entity); await _db.SaveChangesAsync(); return entity; }

        public async Task<bool> DeleteAsync(params object[] key)
        {
            var e = await _set.FindAsync(key);
            if (e == null) return false;

            if (e is ISoftDeletable softDeletable)
            {
                softDeletable.IsDeleted = true;
                _set.Update(e);
            }
            else
            {
                _set.Remove(e);
            }

            await _db.SaveChangesAsync();
            return true;
        }

        public IQueryable<T> Query() => _set.AsNoTracking();
    }
}
