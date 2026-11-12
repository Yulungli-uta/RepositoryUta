using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    /// <summary>
    /// Línea de tiempo de acceso de un usuario: une inicios de sesión, renovaciones, cierres,
    /// sesiones vencidas y eventos de seguimiento en un solo listado ordenado por fecha.
    /// </summary>
    public interface IUserAccessService
    {
        /// <summary>Devuelve null si el usuario no existe. El rango máximo es de 31 días.</summary>
        Task<UserAccessTimelineDto?> GetTimelineAsync(Guid userId, DateTime from, DateTime to, int page, int pageSize, CancellationToken ct);
    }
}
