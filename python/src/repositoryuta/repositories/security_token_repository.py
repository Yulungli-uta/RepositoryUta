from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.identity import SecurityToken


class SecurityTokenRepository:
    """Acceso a auth.tbl_SecurityTokens para flujos de OTP/reset (ver
    AuthService.RequestPasswordChange2FAAsync y afines)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def invalidate_pending(self, user_id: UUID, token_type: str) -> None:
        """Invalida cualquier token pendiente previo del mismo tipo (espejo del
        bucle que marca IsUsed=true en RequestPasswordChange2FAAsync)."""
        now = datetime.now()
        stmt = select(SecurityToken).where(
            SecurityToken.user_id == user_id,
            SecurityToken.token_type == token_type,
            ~SecurityToken.is_used,
            SecurityToken.expires_at > now,
        )
        for token in self._session.scalars(stmt):
            token.is_used = True
        self._session.flush()

    def create(
        self,
        *,
        user_id: UUID,
        token_type: str,
        token_hash: str,
        expires_at: datetime,
        additional_data: str | None = None,
    ) -> SecurityToken:
        row = SecurityToken(
            user_id=user_id,
            token_type=token_type,
            token_hash=token_hash,
            expires_at=expires_at,
            additional_data=additional_data,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def find_valid(self, user_id: UUID, token_type: str, token_hash: str) -> SecurityToken | None:
        now = datetime.now()
        stmt = select(SecurityToken).where(
            SecurityToken.user_id == user_id,
            SecurityToken.token_type == token_type,
            SecurityToken.token_hash == token_hash,
            ~SecurityToken.is_used,
            SecurityToken.expires_at > now,
        )
        return self._session.scalar(stmt)

    def consume(self, token: SecurityToken) -> None:
        token.is_used = True
        self._session.flush()
