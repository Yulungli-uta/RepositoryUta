from uuid import uuid4

import pytest

from repositoryuta.models.application import Application
from repositoryuta.models.identity import User
from repositoryuta.models.notification import NotificationLog, NotificationSubscription
from repositoryuta.models.rbac import Permission, Role, RolePermission, UserRole
from repositoryuta.schemas.auth import TokenPair
from repositoryuta.services import notification_service as svc


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "ok") -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self.text = text


def _active_app(**overrides) -> Application:
    defaults = dict(
        id=uuid4(),
        name="HrFrontend",
        client_id="hr-frontend",
        client_secret_hash="x",
        is_active=True,
        is_deleted=False,
    )
    defaults.update(overrides)
    return Application(**defaults)


# ── create_subscription ───────────────────────────────────────────────────────


def test_create_subscription_success(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()

    subscription_id = svc.create_subscription(
        sqlite_session, app.id, "Login", "https://x/hook", None
    )

    row = sqlite_session.get(NotificationSubscription, subscription_id)
    assert row is not None
    assert row.event_type == "Login"


def test_create_subscription_missing_app_raises(sqlite_session) -> None:
    with pytest.raises(ValueError, match="not found or inactive"):
        svc.create_subscription(sqlite_session, uuid4(), "Login", "https://x/hook", None)


def test_create_subscription_inactive_app_raises(sqlite_session) -> None:
    app = _active_app(is_active=False)
    sqlite_session.add(app)
    sqlite_session.commit()

    with pytest.raises(ValueError, match="not found or inactive"):
        svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", None)


# ── update / delete ────────────────────────────────────────────────────────────


def test_update_subscription_not_found(sqlite_session) -> None:
    assert svc.update_subscription(sqlite_session, uuid4(), "https://x", None, None) is False


def test_update_subscription_success(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()
    subscription_id = svc.create_subscription(
        sqlite_session, app.id, "Login", "https://x/hook", None
    )

    ok = svc.update_subscription(sqlite_session, subscription_id, "https://y/hook", "secret", False)

    assert ok is True
    row = sqlite_session.get(NotificationSubscription, subscription_id)
    assert row.webhook_url == "https://y/hook"
    assert row.secret_key == "secret"
    assert row.is_active is False


def test_delete_subscription_not_found(sqlite_session) -> None:
    assert svc.delete_subscription(sqlite_session, uuid4()) is False


def test_delete_subscription_success(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()
    subscription_id = svc.create_subscription(
        sqlite_session, app.id, "Login", "https://x/hook", None
    )

    ok = svc.delete_subscription(sqlite_session, subscription_id)

    assert ok is True
    assert sqlite_session.get(NotificationSubscription, subscription_id) is None


def test_get_subscriptions_by_application_excludes_inactive(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()
    active_id = svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", None)
    inactive_id = svc.create_subscription(sqlite_session, app.id, "Login", "https://y/hook", None)
    svc.update_subscription(sqlite_session, inactive_id, None, None, False)

    subscriptions = svc.get_subscriptions_by_application(sqlite_session, app.id)

    assert [s.id for s in subscriptions] == [active_id]


# ── stats ────────────────────────────────────────────────────────────────────


def test_get_notification_stats(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()
    subscription_id = svc.create_subscription(
        sqlite_session, app.id, "Login", "https://x/hook", None
    )
    sqlite_session.add(
        NotificationLog(subscription_id=subscription_id, event_type="Login", is_success=True)
    )
    sqlite_session.add(
        NotificationLog(subscription_id=subscription_id, event_type="Login", is_success=False)
    )
    sqlite_session.commit()

    stats = svc.get_notification_stats(sqlite_session)

    assert stats.total_subscriptions == 1
    assert stats.active_subscriptions == 1
    assert stats.total_logs == 2
    assert stats.successful_logs == 1
    assert stats.failed_notifications == 1


def test_get_subscription_stats(sqlite_session) -> None:
    app = _active_app()
    sqlite_session.add(app)
    sqlite_session.commit()
    subscription_id = svc.create_subscription(
        sqlite_session, app.id, "Login", "https://x/hook", None
    )
    sqlite_session.add(
        NotificationLog(subscription_id=subscription_id, event_type="Login", is_success=True)
    )
    sqlite_session.commit()

    stats = svc.get_subscription_stats(sqlite_session, app.id)

    assert len(stats) == 1
    assert stats[0].total_notifications == 1
    assert stats[0].successful_notifications == 1
    assert stats[0].failed_notifications == 0


def test_process_pending_notifications_is_noop() -> None:
    svc.process_pending_notifications()


# ── entrega por webhook ──────────────────────────────────────────────────────


def test_notify_login_event_for_application_sends_webhook(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", "sekret")

    captured = {}

    def _fake_post(url, data=None, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["data"] = data
        return _FakeResponse(200)

    monkeypatch.setattr(svc.requests, "post", _fake_post)

    svc.notify_login_event_for_application(
        sqlite_session,
        user.id,
        "Office365",
        "10.0.0.1",
        "hr-frontend",
        TokenPair(access_token="a", refresh_token="b"),
        "browser-1",
    )

    assert captured["url"] == "https://x/hook"
    assert "X-Webhook-Signature" in captured["headers"]
    assert sqlite_session.query(NotificationLog).filter_by(is_success=True).count() == 1


def test_notify_login_event_for_application_skips_websocket_subscription(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """El unico caso real websocket (login de Azure) ya lo cubre el postMessage
    aditivo — aqui debe omitirse sin intentar ningun envio ni fallar."""
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    subscription = NotificationSubscription(
        application_id=app.id,
        event_type="Login",
        notification_type="websocket",
    )
    sqlite_session.add(subscription)
    sqlite_session.commit()

    def _fail(*a, **k):
        raise AssertionError("no deberia llamarse a requests.post")

    monkeypatch.setattr(svc.requests, "post", _fail)

    svc.notify_login_event_for_application(
        sqlite_session,
        user.id,
        "Office365",
        "10.0.0.1",
        "hr-frontend",
        None,
        "browser-1",
    )

    assert sqlite_session.query(NotificationLog).count() == 0


def test_notify_login_event_for_application_with_delivery_code_omits_pair(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", None)

    captured = {}
    monkeypatch.setattr(
        svc.requests,
        "post",
        lambda url, data=None, headers=None, timeout=None: (
            captured.update(data=data) or _FakeResponse(200)
        ),
    )

    svc.notify_login_event_for_application(
        sqlite_session,
        user.id,
        "Office365",
        None,
        "hr-frontend",
        TokenPair(access_token="a", refresh_token="b"),
        "browser-1",
        delivery_code="one-time-code",
    )

    import json

    payload = json.loads(captured["data"])
    assert payload["pair"] is None
    assert payload["deliveryCode"] == "one-time-code"


def test_notify_login_event_for_application_unknown_app_noop(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(*a, **k):
        raise AssertionError("no deberia llamarse")

    monkeypatch.setattr(svc.requests, "post", _fail)

    svc.notify_login_event_for_application(
        sqlite_session,
        uuid4(),
        "Office365",
        None,
        "no-existe",
        None,
        "browser-1",
    )


def test_notify_login_event_webhook_delivery(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", None)

    monkeypatch.setattr(svc.requests, "post", lambda *a, **k: _FakeResponse(200))

    svc.notify_login_event(
        sqlite_session, user.id, "Local", "10.0.0.1", ["Empleado"], [], None, "b1"
    )

    assert sqlite_session.query(NotificationLog).filter_by(is_success=True).count() == 1


def test_notify_logout_event_never_called_by_anything_but_still_works(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Espejo de NotifyLogoutEventAsync: en el .NET real esta funcion no la
    llama ningun caller (codigo muerto), pero se migra completa por paridad —
    igual que el .NET, que tambien la implementa aunque nunca se invoque."""
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "Logout", "https://x/hook", None)

    monkeypatch.setattr(svc.requests, "post", lambda *a, **k: _FakeResponse(200))

    svc.notify_logout_event(sqlite_session, user.id)

    assert sqlite_session.query(NotificationLog).filter_by(is_success=True).count() == 1


def test_notify_user_created_event(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "UserCreated", "https://x/hook", None)

    monkeypatch.setattr(svc.requests, "post", lambda *a, **k: _FakeResponse(200))

    svc.notify_user_created_event(sqlite_session, user.id)

    assert sqlite_session.query(NotificationLog).filter_by(is_success=True).count() == 1


def test_send_webhook_logs_failure_on_exception(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    sqlite_session.add_all([app, user])
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "UserCreated", "https://x/hook", None)

    def _raise(*a, **k):
        raise ConnectionError("timeout")

    monkeypatch.setattr(svc.requests, "post", _raise)

    svc.notify_user_created_event(sqlite_session, user.id)

    log = sqlite_session.query(NotificationLog).filter_by(is_success=False).first()
    assert log is not None
    assert "timeout" in log.error_message


def test_get_user_roles_and_permissions_for_login_payload(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _active_app()
    user = User(id=uuid4(), email="juan@uta.edu.ec", display_name="Juan", is_active=True)
    role = Role(name="Empleado", is_active=True)
    sqlite_session.add_all([app, user, role])
    sqlite_session.flush()
    permission = Permission(name="ver-perfil", module="Perfil", action="Read")
    sqlite_session.add(permission)
    sqlite_session.flush()
    sqlite_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    sqlite_session.add(UserRole(user_id=user.id, role_id=role.id))
    sqlite_session.commit()
    svc.create_subscription(sqlite_session, app.id, "Login", "https://x/hook", None)

    captured = {}
    monkeypatch.setattr(
        svc.requests,
        "post",
        lambda url, data=None, headers=None, timeout=None: (
            captured.update(data=data) or _FakeResponse(200)
        ),
    )

    svc.notify_login_event_for_application(
        sqlite_session,
        user.id,
        "Office365",
        None,
        "hr-frontend",
        None,
        "browser-1",
    )

    import json

    payload = json.loads(captured["data"])
    assert payload["data"]["roles"] == ["Empleado"]
    assert payload["data"]["permissions"][0]["name"] == "ver-perfil"
