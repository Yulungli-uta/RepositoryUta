using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace WsSeguUta.AuthSystem.API.Data.Repositories
{
  public interface IGenericRepository<T> where T: class
  {
    Task<IEnumerable<T>> GetAllAsync(int page=1,int size=100, Expression<Func<T,bool>>? filter=null, Expression<Func<T,object>>? order=null, bool desc=false);
    Task<T?> GetAsync(params object[] key);
    Task<T> AddAsync(T entity);
    Task<T?> UpdateAsync(T entity);
    Task<bool> DeleteAsync(params object[] key);
  }

  public class GenericRepository<T> : IGenericRepository<T> where T: class
  {
    private readonly AuthDbContext _db; private readonly DbSet<T> _set;
    public GenericRepository(AuthDbContext db){ _db=db; _set=db.Set<T>(); }

    public async Task<IEnumerable<T>> GetAllAsync(int page=1,int size=100, Expression<Func<T,bool>>? filter=null, Expression<Func<T,object>>? order=null, bool desc=false)
    {
      IQueryable<T> q=_set;
      if (filter!=null) q=q.Where(filter);
      if (order!=null) q=desc? q.OrderByDescending(order) : q.OrderBy(order);
      return await q.Skip((page-1)*size).Take(size).ToListAsync();
    }

    public Task<T?> GetAsync(params object[] key)=>_set.FindAsync(key).AsTask();

    public async Task<T> AddAsync(T entity){ _set.Add(entity); await _db.SaveChangesAsync(); return entity; }

    public async Task<T?> UpdateAsync(T entity){ _set.Update(entity); await _db.SaveChangesAsync(); return entity; }

    public async Task<bool> DeleteAsync(params object[] key)
    {
      var e = await _set.FindAsync(key); if (e==null) return false;
      _set.Remove(e); await _db.SaveChangesAsync(); return true;
    }
  }
}
