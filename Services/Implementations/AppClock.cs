using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    /// <summary>
    /// Implementación de <see cref="IAppClock"/> sobre <see cref="TimeProvider"/> (las pruebas pueden inyectar un
    /// <c>FakeTimeProvider</c>). La zona se lee de <c>Time:ZoneId</c>; sin configuración usa America/Guayaquil.
    /// </summary>
    public sealed class AppClock : IAppClock
    {
        /// <summary>Zona por defecto (IANA). En Windows sin ICU se resuelve con el alias "SA Pacific Standard Time".</summary>
        public const string DefaultZoneId = "America/Guayaquil";

        private const string WindowsFallbackZoneId = "SA Pacific Standard Time";

        private readonly TimeProvider _provider;

        public AppClock(TimeProvider provider, IConfiguration configuration)
        {
            ArgumentNullException.ThrowIfNull(provider);
            ArgumentNullException.ThrowIfNull(configuration);
            _provider = provider;
            var zoneId = configuration["Time:ZoneId"];
            Zone = Resolve(string.IsNullOrWhiteSpace(zoneId) ? DefaultZoneId : zoneId.Trim());
        }

        public TimeZoneInfo Zone { get; }

        public DateTimeOffset UtcNow => _provider.GetUtcNow();

        public DateTimeOffset NowOffset => TimeZoneInfo.ConvertTime(_provider.GetUtcNow(), Zone);

        public DateTime Now => NowOffset.DateTime;

        public DateOnly Today => DateOnly.FromDateTime(Now);

        private static TimeZoneInfo Resolve(string zoneId)
        {
            try
            {
                return TimeZoneInfo.FindSystemTimeZoneById(zoneId);
            }
            catch (TimeZoneNotFoundException) when (zoneId == DefaultZoneId)
            {
                return TimeZoneInfo.FindSystemTimeZoneById(WindowsFallbackZoneId);
            }
        }
    }
}
