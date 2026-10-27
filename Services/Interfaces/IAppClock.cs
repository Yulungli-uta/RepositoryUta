namespace WsSeguUta.AuthSystem.API.Services.Interfaces
{
    /// <summary>
    /// Reloj central del sistema (estándar "Fecha y hora UTA"): toda fecha/hora de negocio es hora de Ecuador
    /// (America/Guayaquil, UTC-5, sin horario de verano) y la decide SOLO el servidor, nunca el cliente.
    /// La zona sale de la configuración (<c>Time:ZoneId</c>), no del reloj del servidor ni del contenedor.
    /// </summary>
    public interface IAppClock
    {
        /// <summary>Fecha y hora actual en Ecuador, con <c>Kind = Unspecified</c> (igual que lo que lee EF de un <c>datetime2</c>).</summary>
        DateTime Now { get; }

        /// <summary>Día actual en Ecuador. Usar para "hoy": después de las 19:00 el día UTC ya es el siguiente.</summary>
        DateOnly Today { get; }

        /// <summary>Instante actual con el desfase de Ecuador (-05:00), sin ambigüedad.</summary>
        DateTimeOffset NowOffset { get; }

        /// <summary>Instante actual en UTC. Solo para hablar con sistemas externos que lo exigen (JWT, Microsoft).</summary>
        DateTimeOffset UtcNow { get; }

        /// <summary>Zona horaria del sistema.</summary>
        TimeZoneInfo Zone { get; }
    }
}
