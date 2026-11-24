from sqlalchemy.orm import Session

from repositoryuta.models.audit import AzureSyncLog, HRSyncLog
from repositoryuta.schemas.audit import SyncLogCreate


class SyncLogRepository:
    """AzureSyncLog y HRSyncLog son dos tablas identicas en shape (ver
    _SyncLogColumns en models/audit.py) — un solo repositorio con el modelo
    como parametro, en vez de duplicar la clase."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def log_azure_sync(self, data: SyncLogCreate) -> AzureSyncLog:
        row = AzureSyncLog(**data.model_dump(exclude_none=True))
        self._session.add(row)
        self._session.flush()
        return row

    def log_hr_sync(self, data: SyncLogCreate) -> HRSyncLog:
        row = HRSyncLog(**data.model_dump(exclude_none=True))
        self._session.add(row)
        self._session.flush()
        return row
