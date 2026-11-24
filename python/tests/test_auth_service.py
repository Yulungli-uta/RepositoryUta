from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.core.security.password import hash_password
from repositoryuta.models.access_profile import AccessProfile, UserAccessProfile
from repositoryuta.models.application import Application
from repositoryuta.models.audit import LoginHistory
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.models.rbac import Permission, Role, RolePermission, UserRole
from repositoryuta.models.session import FailedLoginAttempt, UserSession
from repositoryuta.repositories.session_repository import SessionRepository
from repositoryuta.services import auth_service, local_ad_service


def _make_local_user(session, *, email="juan@uta.edu.ec", password="Sup3rSecret", is_active=True):
    user = User(id=uuid4(), email=email, user_type="Local", is_active=is_active)
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


# ── get_ad_groups ────────────────────────────────────────────────────────────


def test_get_ad_groups_returns_empty_when_user_not_in_ad(monkeypatch) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)

    assert auth_service.get_ad_groups("nadie@uta.edu.ec") == []


def test_get_ad_groups_returns_group_names(monkeypatch) -> None:
    ad_user = local_ad_service.DirectoryUser(
        id="guid",
        email="juan@uta.edu.ec",
        display_name="Juan",
        given_name=None,
        surname=None,
        job_title=None,
        department=None,
        is_enabled=True,
    )
    groups = [
        local_ad_service.DirectoryGroup(id="g1", name="Docentes", description=None, email=None),
        local_ad_service.DirectoryGroup(id="g2", name="UActivos", description=None, email=None),
    ]
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: ad_user)
    monkeypatch.setattr(local_ad_service, "get_user_groups", lambda user_id: groups)

    assert auth_service.get_ad_groups("juan@uta.edu.ec") == ["Docentes", "UActivos"]


def test_get_ad_groups_swallows_any_error(monkeypatch) -> None:
    def _raise(email: str) -> None:
        raise RuntimeError("AD unreachable")

    monkeypatch.setattr(local_ad_service, "find_user_by_email", _raise)

    assert auth_service.get_ad_groups("juan@uta.edu.ec") == []


# ── login_local ──────────────────────────────────────────────────────────────


def test_login_local_success_creates_session_and_history(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    pair = auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "Sup3rSecret")

    assert pair is not None
    assert pair.access_token and pair.refresh_token
    sessions = sqlite_session.query(UserSession).filter_by(user_id=user.id).all()
    assert len(sessions) == 1
    assert sessions[0].device_info is None and sessions[0].ip_address is None
    history = sqlite_session.query(LoginHistory).filter_by(user_id=user.id).all()
    assert history[0].login_status == "Success"


def test_login_local_unknown_email_records_failed_attempt(sqlite_session) -> None:
    result = auth_service.login_local(sqlite_session, "nadie@uta.edu.ec", "x")

    assert result is None
    attempts = sqlite_session.query(FailedLoginAttempt).all()
    assert len(attempts) == 1
    history = sqlite_session.query(LoginHistory).all()
    assert history[0].failure_reason == "User not found/inactive"


def test_login_local_rejects_user_without_local_credential(sqlite_session) -> None:
    user = User(id=uuid4(), email="sin-cred@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = auth_service.login_local(sqlite_session, "sin-cred@uta.edu.ec", "x")

    assert result is None
    history = sqlite_session.query(LoginHistory).filter_by(user_id=user.id).one()
    assert history.failure_reason == "No credentials"


def test_login_local_rejects_non_local_user_type(sqlite_session) -> None:
    user = User(id=uuid4(), email="azure@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    assert auth_service.login_local(sqlite_session, "azure@uta.edu.ec", "x") is None


def test_login_local_rejects_inactive_user(sqlite_session) -> None:
    _make_local_user(sqlite_session, email="inactivo@uta.edu.ec", is_active=False)

    assert auth_service.login_local(sqlite_session, "inactivo@uta.edu.ec", "Sup3rSecret") is None


def test_login_local_blocked_when_locked(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    cred = sqlite_session.get(LocalUserCredential, user.id)
    cred.is_locked = True
    sqlite_session.flush()

    assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "Sup3rSecret") is None
    history = sqlite_session.query(LoginHistory).filter_by(user_id=user.id).all()
    assert history[0].login_status == "Blocked"


def test_login_local_rejects_expired_password(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    cred = sqlite_session.get(LocalUserCredential, user.id)
    cred.password_expires_at = datetime.now() - timedelta(days=1)
    sqlite_session.flush()

    assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "Sup3rSecret") is None


def test_login_local_locks_account_after_five_failed_attempts(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    for _ in range(4):
        assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "wrong") is None
    cred = sqlite_session.get(LocalUserCredential, user.id)
    assert cred.is_locked is False

    assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "wrong") is None
    sqlite_session.refresh(cred)
    assert cred.is_locked is True
    assert cred.failed_attempts == 5

    # Ya bloqueada: ni siquiera con la contrasena correcta deja entrar.
    assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "Sup3rSecret") is None


def test_login_local_success_resets_failed_attempts(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    cred = sqlite_session.get(LocalUserCredential, user.id)
    cred.failed_attempts = 3
    sqlite_session.flush()

    assert auth_service.login_local(sqlite_session, "juan@uta.edu.ec", "Sup3rSecret") is not None
    sqlite_session.refresh(cred)
    assert cred.failed_attempts == 0


# ── refresh / reuse detection ────────────────────────────────────────────────


def test_refresh_rotates_session_inheriting_device_and_ip(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    original = sessions.create_session(
        user_id=user.id,
        access_token="old-access",
        refresh_token_hash=auth_service.token_service.hash_token("original-refresh"),
        expires_at=datetime.now() + timedelta(days=7),
        device="iPhone",
        ip_address="10.0.0.5",
    )
    sqlite_session.flush()

    pair = auth_service.refresh(sqlite_session, "original-refresh")

    assert pair is not None
    sqlite_session.refresh(original)
    assert original.is_active is False
    assert original.status == "Rotated"

    new_session = (
        sqlite_session.query(UserSession)
        .filter(UserSession.user_id == user.id, UserSession.is_active.is_(True))
        .one()
    )
    assert new_session.device_info == "iPhone"
    assert new_session.ip_address == "10.0.0.5"


def test_refresh_with_unknown_token_returns_none_without_raising(sqlite_session) -> None:
    assert auth_service.refresh(sqlite_session, "no-existe") is None


def test_refresh_reuse_outside_grace_window_revokes_all_sessions(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    sessions.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash=auth_service.token_service.hash_token("rotated-token"),
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    sessions.create_session(
        user_id=user.id,
        access_token="a2",
        refresh_token_hash="another-hash",
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    sqlite_session.flush()

    rotated_hash = auth_service.token_service.hash_token("rotated-token")
    rotated_row = sqlite_session.query(UserSession).filter_by(refresh_token=rotated_hash).one()
    sessions.revoke_session(rotated_row.session_id, "Rotated")
    rotated_row.revoked_at = datetime.now() - timedelta(minutes=5)
    sqlite_session.flush()

    result = auth_service.refresh(sqlite_session, "rotated-token")

    assert result is None
    active_count = (
        sqlite_session.query(UserSession)
        .filter(UserSession.user_id == user.id, UserSession.is_active.is_(True))
        .count()
    )
    assert active_count == 0


def test_refresh_reuse_not_flagged_when_rotated_session_has_no_revoked_at(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    rotated_hash = auth_service.token_service.hash_token("legacy-rotated")
    sessions.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash=rotated_hash,
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    sqlite_session.flush()

    row = sqlite_session.query(UserSession).filter_by(refresh_token=rotated_hash).one()
    row.is_active = False
    row.status = "Rotated"
    row.revoked_at = None
    sqlite_session.flush()

    # No debe lanzar ni revocar nada: sin revoked_at no hay dato fiable.
    assert auth_service.refresh(sqlite_session, "legacy-rotated") is None


def test_refresh_reuse_within_grace_window_does_not_revoke(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    rotated_hash = auth_service.token_service.hash_token("just-rotated")
    sessions.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash=rotated_hash,
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    other = sessions.create_session(
        user_id=user.id,
        access_token="a2",
        refresh_token_hash="other-hash",
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    sqlite_session.flush()

    row = sqlite_session.query(UserSession).filter_by(refresh_token=rotated_hash).one()
    row.is_active = False
    row.status = "Rotated"
    row.revoked_at = datetime.now() - timedelta(seconds=5)
    sqlite_session.flush()

    assert auth_service.refresh(sqlite_session, "just-rotated") is None
    sqlite_session.refresh(other)
    assert other.is_active is True


# ── logout ───────────────────────────────────────────────────────────────────


def test_logout_revokes_active_session(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    created = sessions.create_session(
        user_id=user.id,
        access_token="a1",
        refresh_token_hash=auth_service.token_service.hash_token("my-refresh"),
        expires_at=datetime.now() + timedelta(days=7),
        device=None,
        ip_address=None,
    )
    sqlite_session.flush()

    assert auth_service.logout(sqlite_session, "my-refresh") is True
    sqlite_session.refresh(created)
    assert created.is_active is False
    assert created.status == "Logout"


def test_logout_is_idempotent_for_unknown_token(sqlite_session) -> None:
    assert auth_service.logout(sqlite_session, "no-existe") is True


# ── validate_token ───────────────────────────────────────────────────────────


def test_validate_token_accepts_valid_user_jwt(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = jwt_core.create_user_token(str(user.id), user.email, ["R_EMPLOYEE"])

    result = auth_service.validate_token(sqlite_session, token)

    assert result.is_valid is True
    assert result.token_type == "JWT"
    assert result.email == user.email


def test_validate_token_reports_inactive_user_found_via_jwt(sqlite_session) -> None:
    user = _make_local_user(sqlite_session, email="inactivo2@uta.edu.ec")
    user.is_active = False
    sqlite_session.flush()
    token = jwt_core.create_user_token(str(user.id), user.email, [])

    result = auth_service.validate_token(sqlite_session, token)

    assert result.is_valid is False
    assert result.message == "User not found or inactive"


def test_validate_token_reports_expired_jwt(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = jwt_core.create_user_token(str(user.id), user.email, [], lifetime_minutes=-5)

    result = auth_service.validate_token(sqlite_session, token)

    assert result.is_valid is False
    assert result.message == "Token expired"


def test_validate_token_treats_non_uuid_subject_as_app_token_candidate(sqlite_session) -> None:
    # sub/nameidentifier que no es un UUID valido: no debe explotar, solo pasar
    # de largo a la rama de app token (y de ahi a "no encontrado").
    payload_token = jwt_core.create_app_token(
        "token-1", "unknown-client", ["R_SIGNATURE_INTEGRATION"], 60
    )

    result = auth_service.validate_token(sqlite_session, payload_token)

    assert result.is_valid is False
    assert result.message == "User not found or inactive"


def test_validate_token_valid_guid_but_no_active_session(sqlite_session) -> None:
    result = auth_service.validate_token(sqlite_session, str(uuid4()))

    assert result.is_valid is False
    assert result.message == "Token is invalid or expired"


def test_validate_token_rejects_tampered_jwt(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = jwt_core.create_user_token(str(user.id), user.email, [])

    result = auth_service.validate_token(sqlite_session, token + "tampered")

    assert result.is_valid is False
    assert result.message == "Token validation failed"


def test_validate_token_reports_user_not_found_or_inactive(sqlite_session) -> None:
    token = jwt_core.create_user_token(str(uuid4()), "fantasma@uta.edu.ec", [])

    result = auth_service.validate_token(sqlite_session, token)

    assert result.is_valid is False
    assert result.message == "User not found or inactive"


def test_validate_token_accepts_valid_app_token(sqlite_session) -> None:
    sqlite_session.add(
        Application(
            name="uta-signature",
            client_id="uta-signature",
            client_secret_hash="hash",
            is_active=True,
        )
    )
    sqlite_session.flush()
    token = jwt_core.create_app_token(
        str(uuid4()), "uta-signature", ["R_SIGNATURE_INTEGRATION"], 60
    )

    result = auth_service.validate_token(sqlite_session, token)

    assert result.is_valid is True
    assert result.token_type == "AppToken"
    assert result.email == "uta-signature"


def test_validate_token_falls_back_to_opaque_session_id(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    sessions = SessionRepository(sqlite_session)
    created = sessions.create_session(
        user_id=user.id,
        access_token="opaque",
        refresh_token_hash="hash-x",
        expires_at=datetime.now() + timedelta(hours=1),
        device=None,
        ip_address=None,
    )
    sqlite_session.flush()

    result = auth_service.validate_token(sqlite_session, str(created.session_id))

    assert result.is_valid is True
    assert result.token_type == "User token"
    assert result.session_id == created.session_id


def test_validate_token_rejects_unknown_non_jwt_string(sqlite_session) -> None:
    result = auth_service.validate_token(sqlite_session, "not-a-jwt-not-a-guid")

    assert result.is_valid is False
    assert result.message == "Token is invalid or expired"


# ── get_me ───────────────────────────────────────────────────────────────────


def test_get_me_aggregates_roles_permissions_and_profiles(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    role = Role(name="R_RH")
    permission = Permission(name="Ver Contratos", module="Contracts", action="Read")
    profile = AccessProfile(name="Directora Administrativa")
    sqlite_session.add_all([role, permission, profile])
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserRole(user_id=user.id, role_id=role.id),
            RolePermission(role_id=role.id, permission_id=permission.id),
            UserAccessProfile(user_id=user.id, access_profile_id=profile.id),
        ]
    )
    sqlite_session.flush()

    me = auth_service.get_me(sqlite_session, user.id)

    assert me is not None
    assert me.roles == ["R_RH"]
    assert me.action_permissions == ["CONTRACTS.READ"]
    assert me.profiles == ["Directora Administrativa"]


def test_get_me_returns_none_for_unknown_user(sqlite_session) -> None:
    assert auth_service.get_me(sqlite_session, uuid4()) is None
