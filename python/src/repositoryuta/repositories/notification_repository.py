from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.notification import NotificationLog, NotificationSubscription
from repositoryuta.schemas.notification import (
    NotificationLogCreate,
    NotificationSubscriptionCreate,
)


class NotificationRepository:
    """Persistencia de NotificationSubscription/NotificationLog. La entrega
    real (webhook HTTP + SignalR) es logica de negocio de NotificationService
    y queda fuera de este corte — ver regla de Fase 0 #13 (SignalR bloqueado)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def create_subscription(
        self, data: NotificationSubscriptionCreate
    ) -> NotificationSubscription:
        row = NotificationSubscription(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row

    def get_subscriptions_by_application(
        self, application_id: UUID
    ) -> list[NotificationSubscription]:
        """Espejo de NotificationService.GetSubscriptionsByApplicationAsync: solo
        activas (el .NET real filtra IsActive, a diferencia de lo que este
        metodo hacia antes de esta correccion)."""
        stmt = select(NotificationSubscription).where(
            NotificationSubscription.application_id == application_id,
            NotificationSubscription.is_active,
        )
        return list(self._session.scalars(stmt))

    def log_notification(self, data: NotificationLogCreate) -> NotificationLog:
        row = NotificationLog(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row
