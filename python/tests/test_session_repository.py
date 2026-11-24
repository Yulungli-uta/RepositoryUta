from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.models.identity import User
from repositoryuta.models.views import VwActiveSession
from repositoryuta.repositories.session_repository import SessionRepository


def test_create_and_get_active_session_by_refresh_hash(sqlite_session) -> None:
    user = User(id=uuid4(), email="ana@uta.edu.ec")
    sqlite_session.add(user)
    sqlite_session.flush()

    repo = SessionRepository(sqlite_session)
    created = repo.create_session(
        user_id=user.id,
        access_token="access",
        refresh_token_hash="refresh-hash",
        expires_at=datetime.now() + timedelta(hours=1),
        device="pytest",
        ip_address="127.0.0.1",
    )

    found = repo.get_active_session_by_refresh_hash("refresh-hash")

    assert found is not None
    session_row, found_user = found
    assert session_row.session_id == created.session_id
    assert found_user.id == user.id


def test_get_active_session_returns_none_when_expired(sqlite_session) -> None:
    user = User(id=uuid4(), email="ana@uta.edu.ec")
    sqlite_session.add(user)
    sqlite_session.flush()

    repo = SessionRepository(sqlite_session)
    repo.create_session(
        user_id=user.id,
        access_token="access",
        refresh_token_hash="expired-hash",
        expires_at=datetime.now() - timedelta(hours=1),
        device=None,
        ip_address=None,
    )

    assert repo.get_active_session_by_refresh_hash("expired-hash") is None


def test_revoke_all_active_sessions_for_user(sqlite_session) -> None:
    user = User(id=uuid4(), email="ana@uta.edu.ec")
    sqlite_session.add(user)
    sqlite_session.flush()

    repo = SessionRepository(sqlite_session)
    repo.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash="r1",
        expires_at=datetime.now() + timedelta(hours=1),
        device=None,
        ip_address=None,
    )
    repo.create_session(
        user_id=user.id,
        access_token="a2",
        refresh_token_hash="r2",
        expires_at=datetime.now() + timedelta(hours=1),
        device=None,
        ip_address=None,
    )

    revoked_count = repo.revoke_all_active_sessions_for_user(user.id, reason="ReuseDetected")

    assert revoked_count == 2
    assert repo.get_active_session_by_refresh_hash("r1") is None
    assert repo.get_active_session_by_refresh_hash("r2") is None


def test_revoke_session_and_get_rotated_session(sqlite_session) -> None:
    user = User(id=uuid4(), email="ana@uta.edu.ec")
    sqlite_session.add(user)
    sqlite_session.flush()

    repo = SessionRepository(sqlite_session)
    created = repo.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash="r1",
        expires_at=datetime.now() + timedelta(hours=1),
        device=None,
        ip_address=None,
    )

    repo.revoke_session(created.session_id, "Rotated")
    sqlite_session.flush()

    rotated = repo.get_rotated_session_by_refresh_hash("r1")
    assert rotated is not None
    assert rotated.is_active is False
    assert rotated.status == "Rotated"


def test_get_active_sessions_orders_by_login_desc(sqlite_session) -> None:
    older = VwActiveSession(
        session_id=uuid4(),
        user_id=uuid4(),
        email="a@uta.edu.ec",
        user_type="Local",
        login_at=datetime(2026, 1, 1),
        expires_at=datetime(2026, 1, 2),
        status="Active",
    )
    newer = VwActiveSession(
        session_id=uuid4(),
        user_id=uuid4(),
        email="b@uta.edu.ec",
        user_type="Local",
        login_at=datetime(2026, 2, 1),
        expires_at=datetime(2026, 2, 2),
        status="Active",
    )
    sqlite_session.add_all([older, newer])
    sqlite_session.flush()

    rows = SessionRepository(sqlite_session).get_active_sessions()

    assert [r.email for r in rows] == ["b@uta.edu.ec", "a@uta.edu.ec"]


def test_record_failed_attempt(sqlite_session) -> None:
    repo = SessionRepository(sqlite_session)

    repo.record_failed_attempt("nadie@uta.edu.ec", "10.0.0.1", "pytest-agent", "bad_password")
    sqlite_session.flush()

    from repositoryuta.models.session import FailedLoginAttempt

    rows = sqlite_session.query(FailedLoginAttempt).all()
    assert len(rows) == 1
    assert rows[0].user_email == "nadie@uta.edu.ec"
    assert rows[0].reason == "bad_password"
