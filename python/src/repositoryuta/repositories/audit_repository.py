
from sqlalchemy.orm import Session

from repositoryuta.core import clock
from repositoryuta.models.audit import (
    AuditLog,
    LoginHistory,
    PermissionChangeHistory,
    RoleChangeHistory,
)
from repositoryuta.schemas.audit import (
    AuditLogCreate,
    LoginHistoryCreate,
    PermissionChangeHistoryCreate,
    RoleChangeHistoryCreate,
)


class AuditRepository:
    """Espejo de AuditService (parte de persistencia) + AuthRepository.InsertLoginAsync.

    Todas estas tablas son de solo insercion (bitacoras) — no hay update/delete
    en el .NET real, salvo los "no-op" explicitos que ya se documentaron en
    Fase 0/3a para PasswordHistory.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def log_action(self, data: AuditLogCreate) -> AuditLog:
        row = AuditLog(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row

    def insert_login(self, data: LoginHistoryCreate) -> LoginHistory:
        # Hora local, igual que el .NET (DateTime.Now): el default de BD es UTC y mezclaria
        # horas distintas en una misma tabla con las sesiones y con lo que escribe el .NET
        row = LoginHistory(**data.model_dump(), login_date_time=clock.now())
        self._session.add(row)
        self._session.flush()
        return row

    def log_role_change(self, data: RoleChangeHistoryCreate) -> RoleChangeHistory:
        row = RoleChangeHistory(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row

    def log_permission_change(
        self, data: PermissionChangeHistoryCreate
    ) -> PermissionChangeHistory:
        row = PermissionChangeHistory(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row
