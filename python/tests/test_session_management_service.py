from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from repositoryuta.core.exceptions import NotFoundError
from repositoryuta.models.application import Application
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.session import UserSession
from repositoryuta.models.views import VwActiveSession
from repositoryuta.services import session_management_service as svc


def test_get_active_sessions_maps_ws_is_active_to_is_websocket_connected(sqlite_session) -> None:
    sqlite_session.add(
        VwActiveSession(
            session_id=uuid4(),
            user_id=uuid4(),
            email="juan@uta.edu.ec",
            user_type="Local",
            login_at=datetime(2026, 1, 1),
            expires_at=datetime(2026, 1, 2),
            status="Active",
            ws_is_active=True,
        )
    )
    sqlite_session.flush()

    sessions = svc.get_active_sessions(sqlite_session)

    assert len(sessions) == 1
    assert sessions[0].is_websocket_connected is True


def test_revoke_session_not_found_raises_not_found_error(sqlite_session) -> None:
    with pytest.raises(NotFoundError):
        svc.revoke_session(sqlite_session, uuid4(), "admin@uta.edu.ec")


def test_revoke_session_marks_inactive_and_logs_audit(sqlite_session) -> None:
    session_row = UserSession(
        session_id=uuid4(),
        user_id=uuid4(),
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now() + timedelta(hours=1),
        is_active=True,
        status="Active",
    )
    sqlite_session.add(session_row)
    sqlite_session.flush()

    result = svc.revoke_session(sqlite_session, session_row.session_id, "admin@uta.edu.ec")

    assert result.was_notified is False
    sqlite_session.refresh(session_row)
    assert session_row.is_active is False
    assert session_row.revoked_by == "admin@uta.edu.ec"
    assert sqlite_session.query(AuditLog).filter_by(action="SessionRevoked").count() == 1


def test_revoke_all_user_sessions_returns_zero_when_none_active(sqlite_session) -> None:
    assert svc.revoke_all_user_sessions(sqlite_session, uuid4(), "admin@uta.edu.ec") == 0


def test_revoke_all_user_sessions_revokes_and_logs(sqlite_session) -> None:
    user_id = uuid4()
    for i in range(2):
        sqlite_session.add(
            UserSession(
                session_id=uuid4(),
                user_id=user_id,
                access_token=f"a{i}",
                refresh_token=f"r{i}",
                expires_at=datetime.now() + timedelta(hours=1),
                is_active=True,
                status="Active",
            )
        )
    sqlite_session.flush()

    count = svc.revoke_all_user_sessions(sqlite_session, user_id, "admin@uta.edu.ec")

    assert count == 2
    assert (
        sqlite_session.query(UserSession)
        .filter_by(user_id=user_id, is_active=True)
        .count()
        == 0
    )
    assert sqlite_session.query(AuditLog).filter_by(action="AllSessionsRevoked").count() == 1


def test_toggle_client_not_found_raises(sqlite_session) -> None:
    with pytest.raises(NotFoundError):
        svc.toggle_client(sqlite_session, uuid4(), "admin@uta.edu.ec")


def test_toggle_client_suspends_and_reactivates(sqlite_session) -> None:
    app = Application(
        name="uta-signature", client_id="uta-signature", client_secret_hash="h", is_active=True
    )
    sqlite_session.add(app)
    sqlite_session.flush()

    suspended = svc.toggle_client(sqlite_session, app.id, "admin@uta.edu.ec")
    assert suspended.is_active is False
    assert "suspendido" in suspended.message.lower()
    sqlite_session.refresh(app)
    assert app.suspended_by == "admin@uta.edu.ec"

    reactivated = svc.toggle_client(sqlite_session, app.id, "admin@uta.edu.ec")
    assert reactivated.is_active is True
    sqlite_session.refresh(app)
    assert app.suspended_at is None
    assert app.suspended_by is None


def test_rotate_secret_not_found_raises(sqlite_session) -> None:
    with pytest.raises(NotFoundError):
        svc.rotate_secret(sqlite_session, uuid4(), "admin@uta.edu.ec")


def test_rotate_secret_changes_hash_and_returns_plaintext_once(sqlite_session) -> None:
    app = Application(
        name="uta-signature", client_id="uta-signature", client_secret_hash="old-hash"
    )
    sqlite_session.add(app)
    sqlite_session.flush()

    result = svc.rotate_secret(sqlite_session, app.id, "admin@uta.edu.ec")

    assert result.new_client_secret
    sqlite_session.refresh(app)
    assert app.client_secret_hash != "old-hash"
    assert app.secret_rotated_by == "admin@uta.edu.ec"


def test_get_active_api_clients_reads_view(sqlite_session) -> None:
    from repositoryuta.models.views import VwActiveApiClient

    sqlite_session.add(
        VwActiveApiClient(
            id=uuid4(),
            name="uta-signature",
            client_id="uta-signature",
            is_active=True,
            created_at=datetime.now(),
            calls_last_24h=0,
        )
    )
    sqlite_session.flush()

    clients = svc.get_active_api_clients(sqlite_session)

    assert len(clients) == 1
    assert clients[0].client_id == "uta-signature"
