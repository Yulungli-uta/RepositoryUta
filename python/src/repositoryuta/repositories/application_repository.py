from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from repositoryuta.models.application import Application, LegacyAuthLog
from repositoryuta.models.views import VwActiveApiClient
from repositoryuta.schemas.application import LegacyAuthLogCreate


class ApplicationRepository:
    """Espejo de ApplicationRepository (Data/Repositories/ApplicationRepository.cs)
    + la parte de solo-lectura de LegacyAuthLog/vw_ActiveApiClients que hoy vive
    directo en SessionManagementService (persistencia, no negocio)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def exists_active_client(self, client_id: str) -> bool:
        stmt = select(Application.id).where(
            Application.client_id == client_id,
            Application.is_active,
            ~Application.is_deleted,
        )
        return self._session.scalar(stmt) is not None

    def find_active_by_client_id(self, client_id: str) -> Application | None:
        """Espejo de AppAuthService: `a.ClientId == clientId && a.IsActive && !a.IsDeleted`."""
        stmt = select(Application).where(
            Application.client_id == client_id,
            Application.is_active,
            ~Application.is_deleted,
        )
        return self._session.scalar(stmt)

    def find_by_client_id(self, client_id: str) -> Application | None:
        """Espejo de GetApplicationStatsAsync: `a.ClientId == clientId && !a.IsDeleted`
        (sin exigir IsActive — permite ver stats de una app ya suspendida)."""
        stmt = select(Application).where(
            Application.client_id == client_id, ~Application.is_deleted
        )
        return self._session.scalar(stmt)

    def find_not_deleted(self, application_id: UUID) -> Application | None:
        """Espejo de ToggleClientAsync/RotateSecretAsync: busca por Id + no
        eliminada (sin exigir is_active — a diferencia de exists_active_client,
        aqui se necesita poder encontrar tambien una app ya suspendida para
        poder reactivarla)."""
        stmt = select(Application).where(
            Application.id == application_id, ~Application.is_deleted
        )
        return self._session.scalar(stmt)

    def log_legacy_auth(self, data: LegacyAuthLogCreate) -> LegacyAuthLog:
        row = LegacyAuthLog(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row

    def get_legacy_auth_log_stats(self, application_id: UUID) -> tuple[int, int, int]:
        """Espejo del GroupBy de GetApplicationStatsAsync: (total, exitosos,
        ultimos 7 dias). Devuelve (0, 0, 0) si no hay filas, igual que el
        `logAgg?.Total ?? 0` del .NET."""
        cutoff = datetime.now() - timedelta(days=7)
        stmt = select(
            func.count(),
            func.sum(func.iif(LegacyAuthLog.auth_result == "Success", 1, 0)),
            func.sum(func.iif(LegacyAuthLog.created_at >= cutoff, 1, 0)),
        ).where(LegacyAuthLog.application_id == application_id)
        total, successful, last_7_days = self._session.execute(stmt).one()
        return total or 0, successful or 0, last_7_days or 0

    def get_active_api_clients(self) -> list[VwActiveApiClient]:
        stmt = select(VwActiveApiClient).order_by(
            VwActiveApiClient.last_used_at.desc(), VwActiveApiClient.name
        )
        return list(self._session.scalars(stmt))
