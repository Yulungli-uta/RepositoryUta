from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import select

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.core.security.password import hash_password
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.identity import LocalUserCredential, User, UserActivityLog
from repositoryuta.models.session import UserSession
from repositoryuta.services import activity_log_service
from repositoryuta.services.session_housekeeping_service import run_housekeeping_once
from repositoryuta.services.user_access_service import describe_device


def _make_local_user(session, *, email="juan@uta.edu.ec", password="OldPass1") -> User:
    user = User(id=uuid4(), email=email, user_type="Local", is_active=True)
    session.add(user)
    session.flush()
    session.add(
        LocalUserCredential(
            user_id=user.id,
            password_hash=hash_password(password),
            password_created_at=datetime.now(),
        )
    )
    session.flush()
    return user


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def _login(client, email="juan@uta.edu.ec", password="OldPass1") -> dict:
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["data"]


def _activities(session, user_id) -> list[UserActivityLog]:
    return list(session.scalars(select(UserActivityLog).where(UserActivityLog.user_id == user_id)))


# ── logout con motivo ────────────────────────────────────────────────────────


def test_logout_with_allowed_reason_is_recorded(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    tokens = _login(client)

    response = client.post(
        "/api/auth/logout",
        json={"refresh_token": tokens["refreshToken"], "reason": "PERMISSIONS_RECOVERY"},
    )

    assert response.status_code == 200
    rows = _activities(sqlite_session, user.id)
    assert [r.activity for r in rows] == [activity_log_service.SESSION_RESET_AUTO]
    assert "PERMISSIONS_RECOVERY" in (rows[0].activity_details or "")


def test_logout_ignores_free_text_reason(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    tokens = _login(client)

    client.post(
        "/api/auth/logout",
        json={"refresh_token": tokens["refreshToken"], "reason": "texto libre del cliente"},
    )

    assert _activities(sqlite_session, user.id) == []


def test_plain_logout_does_not_log_activity(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    tokens = _login(client)

    client.post("/api/auth/logout", json={"refresh_token": tokens["refreshToken"]})

    assert _activities(sqlite_session, user.id) == []


# ── renovación rechazada ─────────────────────────────────────────────────────


def test_refresh_of_expired_session_is_rejected_and_logged(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    tokens = _login(client)
    row = sqlite_session.scalar(select(UserSession).where(UserSession.user_id == user.id))
    row.expires_at = datetime.now() - timedelta(minutes=1)
    sqlite_session.flush()

    response = client.post("/api/auth/refresh", json={"refresh_token": tokens["refreshToken"]})

    assert response.status_code == 401
    rows = _activities(sqlite_session, user.id)
    assert [r.activity for r in rows] == [activity_log_service.REFRESH_REJECTED]
    assert "EXPIRED" in (rows[0].activity_details or "")
    # El motivo exacto no se devuelve al cliente
    assert "EXPIRED" not in response.text


# ── menú vacío ───────────────────────────────────────────────────────────────


def test_empty_menu_is_logged(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = create_user_token(str(user.id), user.email, [])

    response = client.get("/api/menu/user", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["data"] == []
    rows = _activities(sqlite_session, user.id)
    assert [r.activity for r in rows] == [activity_log_service.MENU_LOAD_EMPTY]


# ── línea de tiempo ──────────────────────────────────────────────────────────


def test_timeline_requires_admin_role(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = create_user_token(str(user.id), user.email, ["R_EMPLOYEE"])

    response = client.get(
        f"/api/user-access/{user.id}/timeline", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403


def test_timeline_unknown_user_returns_404(client, sqlite_session) -> None:
    response = client.get(f"/api/user-access/{uuid4()}/timeline", headers=_admin_header())

    assert response.status_code == 404


def test_timeline_separates_login_renewal_and_logout(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    tokens = _login(client)
    renewed = client.post("/api/auth/refresh", json={"refresh_token": tokens["refreshToken"]})
    assert renewed.status_code == 200
    client.post(
        "/api/auth/logout",
        json={
            "refresh_token": renewed.json()["data"]["refreshToken"],
            "reason": "PERMISSIONS_RECOVERY",
        },
    )

    response = client.get(f"/api/user-access/{user.id}/timeline", headers=_admin_header())

    assert response.status_code == 200
    data = response.json()["data"]
    types = [item["type"] for item in data["items"]]
    assert {"LOGIN", "SESSION_RENEWED", "LOGOUT", "ACTIVITY"} <= set(types)
    assert data["summary"]["email"] == user.email
    assert data["summary"]["validSessions"] == 0
    assert data["totalCount"] == len(types)
    # Los tokens nunca viajan en la línea de tiempo
    assert tokens["accessToken"] not in response.text
    assert tokens["refreshToken"] not in response.text


def test_timeline_clamps_range_and_page_size(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.get(
        f"/api/user-access/{user.id}/timeline",
        params={"from": "2020-01-01T00:00:00", "to": "2026-01-01T00:00:00", "pageSize": 100000},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["pageSize"] == 200


# ── mantenimiento ────────────────────────────────────────────────────────────


def _session_row(user_id, *, expires_at, active=True) -> UserSession:
    return UserSession(
        user_id=user_id,
        access_token="a",
        refresh_token=uuid4().hex,
        expires_at=expires_at,
        is_active=active,
        status="Active" if active else "Logout",
    )


def test_housekeeping_marks_only_expired_active_sessions(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    now = datetime.now()
    expired = _session_row(user.id, expires_at=now - timedelta(days=1))
    valid = _session_row(user.id, expires_at=now + timedelta(days=1))
    closed = _session_row(user.id, expires_at=now - timedelta(days=1), active=False)
    sqlite_session.add_all([expired, valid, closed])
    sqlite_session.flush()

    expired_count, _ = run_housekeeping_once(sqlite_session, now=now)

    assert expired_count == 1
    sqlite_session.refresh(expired)
    sqlite_session.refresh(valid)
    sqlite_session.refresh(closed)
    assert (expired.is_active, expired.status) == (False, "Expired")
    assert (valid.is_active, valid.status) == (True, "Active")
    assert closed.status == "Logout"


def test_housekeeping_purges_old_activity_but_keeps_recent(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    now = datetime.now()
    for activity, age_days in (("OLD", 120), ("RECENT", 5)):
        sqlite_session.add(
            UserActivityLog(
                user_id=user.id, activity=activity, timestamp=now - timedelta(days=age_days)
            )
        )
    sqlite_session.flush()

    _, purged = run_housekeeping_once(sqlite_session, retention_days=90, now=now)

    assert purged == 1
    assert [r.activity for r in _activities(sqlite_session, user.id)] == ["RECENT"]


# ── dispositivo legible ──────────────────────────────────────────────────────


def test_describe_device() -> None:
    android_chrome = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/155.0"
    windows_edge = "Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537.36 Chrome/120.0 Edg/120.0"
    assert describe_device(None, android_chrome) == "Chrome · Android"
    assert describe_device(None, windows_edge) == "Edge · Windows"
    assert describe_device("Chrome 155 | Linux", None) == "Chrome 155 | Linux"
    assert describe_device(None, None) is None


# ── sesiones del mismo navegador ─────────────────────────────────────────────


def _login_with_browser(client, browser_id) -> dict:
    response = client.post(
        "/api/auth/login",
        json={"email": "juan@uta.edu.ec", "password": "OldPass1", "browserId": browser_id},
    )
    assert response.status_code == 200
    return response.json()["data"]


def test_new_login_closes_previous_sessions_of_same_browser(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _login_with_browser(client, "browser-1")
    _login_with_browser(client, "browser-2")  # otro navegador: no se toca

    _login_with_browser(client, "browser-1")

    rows = list(
        sqlite_session.scalars(
            select(UserSession)
            .where(UserSession.user_id == user.id)
            .order_by(UserSession.created_at)
        )
    )
    by_browser = [(r.browser_id, r.status) for r in rows]
    assert by_browser == [
        ("browser-1", "Superseded"),
        ("browser-2", "Active"),
        ("browser-1", "Active"),
    ]


def test_login_without_browser_id_does_not_close_sessions(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    client.post("/api/auth/login", json={"email": "juan@uta.edu.ec", "password": "OldPass1"})
    client.post("/api/auth/login", json={"email": "juan@uta.edu.ec", "password": "OldPass1"})

    statuses = list(
        sqlite_session.scalars(select(UserSession.status).where(UserSession.user_id == user.id))
    )
    assert statuses == ["Active", "Active"]


def test_timeline_shows_superseded_session(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _login_with_browser(client, "browser-1")
    _login_with_browser(client, "browser-1")

    response = client.get(f"/api/user-access/{user.id}/timeline", headers=_admin_header())

    titles = [item["title"] for item in response.json()["data"]["items"]]
    assert "Sesión reemplazada" in titles


# ── bloqueo de cuentas Local ─────────────────────────────────────────────────


def _lock(session, user, *, minutes: int | None) -> None:
    cred = session.get(LocalUserCredential, user.id)
    cred.failed_attempts = 5
    cred.is_locked = True
    cred.locked_until = datetime.now() + timedelta(minutes=minutes) if minutes is not None else None
    session.flush()


def test_lock_does_not_expire_by_itself(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _lock(sqlite_session, user, minutes=-1)  # la fecha de referencia ya paso

    response = client.post("/api/auth/login", json={"email": user.email, "password": "OldPass1"})

    # Solo un administrador lo levanta (boton "Desbloquear")
    assert response.status_code == 401
    cred = sqlite_session.get(LocalUserCredential, user.id)
    assert cred.is_locked is True


def test_active_lock_still_blocks_login(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _lock(sqlite_session, user, minutes=20)

    response = client.post("/api/auth/login", json={"email": user.email, "password": "OldPass1"})

    assert response.status_code == 401


def test_manual_lock_without_date_stays_until_unlocked(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _lock(sqlite_session, user, minutes=None)

    response = client.post("/api/auth/login", json={"email": user.email, "password": "OldPass1"})

    assert response.status_code == 401


def test_unlock_endpoint_clears_lock_and_is_audited(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _lock(sqlite_session, user, minutes=20)

    response = client.post(f"/api/local-credentials/{user.id}/unlock", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"] == {"unlocked": True, "wasLocked": True}
    cred = sqlite_session.get(LocalUserCredential, user.id)
    assert (cred.is_locked, cred.failed_attempts, cred.locked_until) == (False, 0, None)
    audit = list(
        sqlite_session.scalars(select(AuditLog).where(AuditLog.action == "AccountUnlocked"))
    )
    assert len(audit) == 1 and "UnlockedBy=admin@uta.edu.ec" in (audit[0].new_values or "")
    ok = client.post("/api/auth/login", json={"email": user.email, "password": "OldPass1"})
    assert ok.status_code == 200


def test_unlock_requires_admin_role_and_existing_user(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    employee = create_user_token(str(user.id), user.email, ["R_EMPLOYEE"])

    denied = client.post(
        f"/api/local-credentials/{user.id}/unlock", headers={"Authorization": f"Bearer {employee}"}
    )
    missing = client.post(f"/api/local-credentials/{uuid4()}/unlock", headers=_admin_header())

    assert denied.status_code == 403
    assert missing.status_code == 404


def test_timeline_summary_reports_locked_account(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    _lock(sqlite_session, user, minutes=20)

    response = client.get(f"/api/user-access/{user.id}/timeline", headers=_admin_header())

    summary = response.json()["data"]["summary"]
    assert summary["accountLocked"] is True
    assert summary["lockedUntil"] is not None
