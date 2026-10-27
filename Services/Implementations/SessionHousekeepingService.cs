using Microsoft.EntityFrameworkCore;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Services.Implementations
{
    /// <summary>
    /// Mantenimiento periódico: marca como vencidas las sesiones cuyo ExpiresAt ya pasó (nada más
    /// las cierra: solo cambiaban de estado al renovarse, cerrar sesión o ser revocadas) y limpia
    /// la bitácora de eventos antigua. Se desactiva con SessionHousekeeping:Enabled=false.
    /// </summary>
    public class SessionHousekeepingService : BackgroundService
    {
        private const int ExpireBatchSize = 2000;
        private const int MaxBatchesPerRun = 20;
        private const int PurgeBatchSize = 5000;

        private static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

        private readonly IServiceScopeFactory _scopes;
        private readonly IConfiguration _cfg;
        private readonly ILogger<SessionHousekeepingService> _logger;

        public SessionHousekeepingService(IServiceScopeFactory scopes, IConfiguration cfg, ILogger<SessionHousekeepingService> logger)
        {
            _scopes = scopes;
            _cfg = cfg;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_cfg.GetValue("SessionHousekeeping:Enabled", true)) return;

            try
            {
                await Task.Delay(StartupDelay, stoppingToken);
                using var timer = new PeriodicTimer(Interval);
                do
                {
                    await RunOnceAsync(stoppingToken);
                } while (await timer.WaitForNextTickAsync(stoppingToken));
            }
            catch (OperationCanceledException)
            {
                // apagado normal de la aplicación
            }
        }

        private async Task RunOnceAsync(CancellationToken ct)
        {
            try
            {
                using var scope = _scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
                var clock = scope.ServiceProvider.GetRequiredService<IAppClock>();
                var retentionDays = Math.Max(30, _cfg.GetValue("SessionHousekeeping:ActivityLogRetentionDays", 90));

                var expired = 0;
                for (var i = 0; i < MaxBatchesPerRun; i++)
                {
                    var now = clock.Now;
                    var batch = await db.UserSessions
                        .Where(s => s.IsActive && s.ExpiresAt < now)
                        .OrderBy(s => s.ExpiresAt)
                        .Take(ExpireBatchSize)
                        .Select(s => s.SessionId)
                        .ToListAsync(ct);
                    if (batch.Count == 0) break;

                    expired += await db.UserSessions
                        .Where(s => batch.Contains(s.SessionId) && s.IsActive)
                        .ExecuteUpdateAsync(set => set
                            .SetProperty(s => s.IsActive, false)
                            .SetProperty(s => s.Status, "Expired"), ct);
                }

                var cutoff = clock.Now.AddDays(-retentionDays);
                var purged = 0;
                int deleted;
                do
                {
                    var ids = await db.UserActivityLogs
                        .Where(a => a.Timestamp < cutoff)
                        .OrderBy(a => a.Id)
                        .Take(PurgeBatchSize)
                        .Select(a => a.Id)
                        .ToListAsync(ct);
                    deleted = ids.Count == 0
                        ? 0
                        : await db.UserActivityLogs.Where(a => ids.Contains(a.Id)).ExecuteDeleteAsync(ct);
                    purged += deleted;
                } while (deleted == PurgeBatchSize);

                if (expired > 0 || purged > 0)
                    _logger.LogInformation("Mantenimiento de sesiones: {Expired} sesiones marcadas como vencidas, {Purged} eventos antiguos eliminados", expired, purged);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falló el mantenimiento de sesiones; se reintenta en el siguiente ciclo");
            }
        }
    }
}
