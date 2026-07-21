namespace WsSeguUta.AuthSystem.API.Models.Entities;

/// <summary>
/// Marca una entidad como soft-delete: "eliminar" pone <see cref="IsDeleted"/> en true
/// en vez de borrar la fila físicamente. El repositorio genérico (<c>GenericRepository&lt;T&gt;</c>)
/// detecta esta interfaz en <c>DeleteAsync</c>; <c>AuthDbContext.OnModelCreating</c> aplica un
/// filtro global de consulta para excluir automáticamente las filas marcadas de toda consulta
/// EF Core normal (no aplica a SQL/Dapper crudo, que debe filtrar manualmente si lo usa).
/// </summary>
public interface ISoftDeletable
{
    bool IsDeleted { get; set; }
}
