using AutoMapper;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    public class CrudService<TEntity, TCreate, TUpdate> : ICrudService<TEntity, TCreate, TUpdate>
        where TEntity : class, new()
    {
        private readonly IGenericRepository<TEntity> _repo;
        private readonly IMapper _map;

        public CrudService(IGenericRepository<TEntity> repo, IMapper map)
        {
            _repo = repo;
            _map = map;
        }

        public Task<PagedResult<TEntity>> ListAsync(int page, int pageSize, CancellationToken ct = default) =>
            _repo.GetPagedAsync(page, pageSize, ct);

        public Task<TEntity?> GetAsync(params object[] key) =>
            _repo.GetAsync(key);

        public async Task<TEntity> CreateAsync(TCreate dto)
        {
            var entity = _map.Map<TEntity>(dto);
            return await _repo.AddAsync(entity);
        }

        public async Task<TEntity?> UpdateAsync(object key, TUpdate dto)
        {
            var current = await _repo.GetAsync(key);
            if (current == null) return null;
            _map.Map(dto, current);
            return await _repo.UpdateAsync(current);
        }

        public Task<bool> DeleteAsync(params object[] key) =>
            _repo.DeleteAsync(key);
    }
}
