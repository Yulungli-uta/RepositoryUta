from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from repositoryuta.models.identity import User
from repositoryuta.models.session import FailedLoginAttempt, UserSession
from repositoryuta.models.views import VwActiveSession


class SessionRepository:
    """Espejo de AuthRepository (Data/Repositories/_Specialized.cs), acotado a lo
    que corresponde a este corte (UserSession, FailedLoginAttempt).
    InsertLoginAsync (LoginHistory) queda para el corte de Auditoria/historial,
    fuera de este slice.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_session(
        self,
        *,
        user_id: UUID,
        access_token: str,
        refresh_token_hash: str,
        expires_at: datetime,
        device: str | None,
        ip_address: str | None,
        user_agent: str | None = None,
        browser_id: str | None = None,
        session_id: UUID | None = None,
    ) -> UserSession:
        session_row = UserSession(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token_hash,
            expires_at=expires_at,
            device_info=device,
            ip_address=ip_address,
            user_agent=user_agent,
            browser_id=browser_id,
            is_active=True,
            status="Active",
        )
        if session_id is not None:
            session_row.session_id = session_id
        self._session.add(session_row)
        self._session.flush()
        return session_row

    def get_active_session_by_refresh_hash(
        self, refresh_hash: str
    ) -> tuple[UserSession, User] | None:
        now = datetime.now()
        session_row = self._session.scalar(
            select(UserSession).where(
                UserSession.refresh_token == refresh_hash,
                UserSession.is_active,
                UserSession.expires_at > now,
            )
        )
        if session_row is None:
            return None

        user = self._session.scalar(
            select(User).where(User.id == session_row.user_id, User.is_active)
        )
        if user is None:
            return None
        return session_row, user

    def get_rotated_session_by_refresh_hash(self, refresh_hash: str) -> UserSession | None:
        """Sesion INACTIVA cuyo refresh token fue rotado: presentar un token ya
        rotado es el indicador mas fiable de robo (ver AuthRepository)."""
        stmt = select(UserSession).where(
            UserSession.refresh_token == refresh_hash,
            ~UserSession.is_active,
            UserSession.status == "Rotated",
        )
        return self._session.scalar(stmt)

    def revoke_all_active_sessions_for_user(self, user_id: UUID, reason: str) -> int:
        """UPDATE en bloque sin cargar entidades — espejo de
        RevokeAllActiveSessionsForUserAsync (ExecuteUpdateAsync en .NET)."""
        stmt = (
            update(UserSession)
            .where(UserSession.user_id == user_id, UserSession.is_active)
            .values(
                is_active=False, status=reason, revoked_at=datetime.now(), revoked_by="System"
            )
        )
        result = self._session.execute(stmt)
        return result.rowcount

    def revoke_session(self, session_id: UUID, reason: str) -> None:
        session_row = self._session.get(UserSession, session_id)
        if session_row is None:
            return
        session_row.is_active = False
        session_row.status = reason or "Revoked"
        session_row.revoked_at = datetime.now()
        self._session.flush()

    def is_session_active(self, session_id: UUID) -> bool | None:
        """Espejo del chequeo de revocacion en AuthService.ValidateTokenAsync (.NET):
        None si la sesion no existe (token con "sid" desconocido, no se bloquea por
        eso), True/False segun IsActive si existe."""
        return self._session.scalar(
            select(UserSession.is_active).where(UserSession.session_id == session_id)
        )

    def find_active_by_session_id(self, session_id: UUID) -> UserSession | None:
        """Rama legado de ValidateTokenAsync: trata el propio SessionId como un
        "token opaco" cuando el string recibido no es un JWT valido."""
        now = datetime.now()
        stmt = select(UserSession).where(
            UserSession.session_id == session_id,
            UserSession.is_active,
            UserSession.expires_at > now,
        )
        return self._session.scalar(stmt)

    def find_active_session_by_id(self, session_id: UUID) -> UserSession | None:
        """Espejo de SessionManagementService.RevokeSessionAsync: busca por
        SessionId + IsActive, SIN chequear expiracion — a diferencia de
        find_active_by_session_id (usado por validate_token), un admin debe
        poder revocar una sesion ya expirada pero que sigue marcada activa.
        """
        stmt = select(UserSession).where(
            UserSession.session_id == session_id, UserSession.is_active
        )
        return self._session.scalar(stmt)

    def revoke_session_by_admin(self, session_row: UserSession, revoked_by: str) -> None:
        """A diferencia de revoke_session() (usado en refresh/logout, sin
        RevokedBy), este SI registra quien la revoco — espejo de
        RevokeSessionAsync del panel de administracion."""
        session_row.is_active = False
        session_row.status = "Revoked"
        session_row.revoked_at = datetime.now()
        session_row.revoked_by = revoked_by
        self._session.flush()

    def revoke_all_sessions_by_admin(self, user_id: UUID, revoked_by: str) -> list[UserSession]:
        """Espejo de RevokeAllUserSessionsAsync: carga las entidades (no un
        UPDATE en bloque) porque el .NET itera cada una para buscar su conexion
        WS — ese paso esta fuera de alcance aqui (regla de Fase 0 #13), pero se
        preserva la carga completa para poder contarlas/auditarlas igual.
        """
        stmt = select(UserSession).where(
            UserSession.user_id == user_id, UserSession.is_active
        )
        sessions = list(self._session.scalars(stmt))
        now = datetime.now()
        for session_row in sessions:
            session_row.is_active = False
            session_row.status = "Revoked"
            session_row.revoked_at = now
            session_row.revoked_by = revoked_by
        self._session.flush()
        return sessions

    def get_active_sessions(self) -> list[VwActiveSession]:
        """Espejo de SessionManagementService (parte de persistencia): lee
        auth.vw_ActiveSessions completa, ordenada por login mas reciente."""
        stmt = select(VwActiveSession).order_by(VwActiveSession.login_at.desc())
        return list(self._session.scalars(stmt))

    def record_failed_attempt(
        self,
        email: str,
        ip_address: str | None,
        user_agent: str | None,
        reason: str | None,
    ) -> None:
        self._session.add(
            FailedLoginAttempt(
                user_email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                reason=reason,
                attempted_at=datetime.now(),
            )
        )
        self._session.flush()
