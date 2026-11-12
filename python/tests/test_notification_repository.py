from uuid import uuid4

from repositoryuta.repositories.notification_repository import NotificationRepository
from repositoryuta.schemas.notification import (
    NotificationLogCreate,
    NotificationSubscriptionCreate,
)


def test_create_subscription_and_get_by_application(sqlite_session) -> None:
    application_id = uuid4()
    repo = NotificationRepository(sqlite_session)

    created = repo.create_subscription(
        NotificationSubscriptionCreate(
            application_id=application_id,
            event_type="Login",
            webhook_url="https://example.uta.edu.ec/webhook",
        )
    )

    subscriptions = repo.get_subscriptions_by_application(application_id)

    assert created.id is not None
    assert [s.id for s in subscriptions] == [created.id]


def test_get_subscriptions_by_application_excludes_inactive(sqlite_session) -> None:
    application_id = uuid4()
    repo = NotificationRepository(sqlite_session)
    repo.create_subscription(
        NotificationSubscriptionCreate(
            application_id=application_id,
            event_type="Login",
            webhook_url="https://example.uta.edu.ec/webhook",
        )
    )
    inactive = repo.create_subscription(
        NotificationSubscriptionCreate(
            application_id=application_id,
            event_type="Login",
            webhook_url="https://example.uta.edu.ec/webhook2",
        )
    )
    inactive.is_active = False
    sqlite_session.flush()

    subscriptions = repo.get_subscriptions_by_application(application_id)

    assert len(subscriptions) == 1
    assert subscriptions[0].id != inactive.id


def test_log_notification(sqlite_session) -> None:
    repo = NotificationRepository(sqlite_session)

    row = repo.log_notification(
        NotificationLogCreate(subscription_id=uuid4(), event_type="Login", is_success=True)
    )

    assert row.id is not None
    assert row.is_success is True
