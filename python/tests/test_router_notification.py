from datetime import datetime
from uuid import uuid4

import pytest

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.schemas.notification import (
    NotificationStatsRead,
    SubscriptionStatsRead,
)
from repositoryuta.services import notification_service as svc


def _auth_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "juan@uta.edu.ec", ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def test_create_subscription_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    sub_id = uuid4()
    monkeypatch.setattr(svc, "create_subscription", lambda session, aid, et, wu, sk: sub_id)

    response = client.post(
        "/api/notifications/subscriptions",
        json={
            "applicationId": str(uuid4()),
            "eventType": "Login",
            "webhookUrl": "https://x/hook",
        },
        headers=_auth_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["subscriptionId"] == str(sub_id)


def test_create_subscription_invalid_app_returns_400(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(session, aid, et, wu, sk):
        raise ValueError("Application not found or inactive")

    monkeypatch.setattr(svc, "create_subscription", _raise)

    response = client.post(
        "/api/notifications/subscriptions",
        json={
            "applicationId": str(uuid4()),
            "eventType": "Login",
            "webhookUrl": "https://x/hook",
        },
        headers=_auth_header(),
    )

    assert response.status_code == 400


def test_create_subscription_requires_auth(client) -> None:
    response = client.post(
        "/api/notifications/subscriptions",
        json={"applicationId": str(uuid4()), "eventType": "Login", "webhookUrl": "https://x/hook"},
    )
    assert response.status_code == 401


def test_update_subscription_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "update_subscription", lambda session, sid, wu, sk, ia: False)

    response = client.put(
        f"/api/notifications/subscriptions/{uuid4()}", json={}, headers=_auth_header()
    )

    assert response.status_code == 404


def test_update_subscription_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "update_subscription", lambda session, sid, wu, sk, ia: True)

    response = client.put(
        f"/api/notifications/subscriptions/{uuid4()}",
        json={"isActive": False},
        headers=_auth_header(),
    )

    assert response.status_code == 200


def test_delete_subscription_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "delete_subscription", lambda session, sid: False)

    response = client.delete(f"/api/notifications/subscriptions/{uuid4()}", headers=_auth_header())

    assert response.status_code == 404


def test_delete_subscription_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "delete_subscription", lambda session, sid: True)

    response = client.delete(f"/api/notifications/subscriptions/{uuid4()}", headers=_auth_header())

    assert response.status_code == 200


def test_get_subscriptions_by_application(client, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Row:
        id = uuid4()
        application_id = uuid4()
        event_type = "Login"
        webhook_url = "https://x/hook"
        notification_type = "webhook"
        is_active = True
        created_at = datetime.now()
        modified_at = None

    monkeypatch.setattr(svc, "get_subscriptions_by_application", lambda session, aid: [_Row()])

    response = client.get(
        f"/api/notifications/subscriptions/application/{uuid4()}", headers=_auth_header()
    )

    assert response.status_code == 200
    assert response.json()["data"][0]["eventType"] == "Login"


def test_get_notification_stats(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc, "get_notification_stats",
        lambda session: NotificationStatsRead(
            total_subscriptions=1, active_subscriptions=1, total_logs=2,
            successful_logs=1, failed_notifications=1,
        ),
    )

    response = client.get("/api/notifications/stats", headers=_auth_header())

    assert response.status_code == 200
    assert response.json()["data"]["totalSubscriptions"] == 1


def test_get_subscription_stats(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc, "get_subscription_stats",
        lambda session, aid: [
            SubscriptionStatsRead(
                subscription_id=uuid4(), event_type="Login", webhook_url="https://x",
                is_active=True, total_notifications=1, successful_notifications=1,
                failed_notifications=0, last_modified=None,
            )
        ],
    )

    response = client.get(
        f"/api/notifications/stats/application/{uuid4()}", headers=_auth_header()
    )

    assert response.status_code == 200
    assert len(response.json()["data"]) == 1


def test_process_pending_notifications(client, monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(svc, "process_pending_notifications", lambda: called.append(True))

    response = client.post("/api/notifications/process-pending", headers=_auth_header())

    assert response.status_code == 200
    assert called == [True]


def test_webhook_test_allows_anonymous(client) -> None:
    response = client.post("/api/notifications/webhook-test", json={"hello": "world"})

    assert response.status_code == 200
    body = response.json()
    assert body["Status"] == "Success"
    assert body["ReceivedPayload"] == {"hello": "world"}
