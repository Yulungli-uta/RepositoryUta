from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.jwt import CLAIM_ROLE, decode_token
from repositoryuta.core.security.password import hash_password
from repositoryuta.models.application import Application, LegacyAuthLog
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.models.rbac import Permission, Role, RolePermission, UserRole
from repositoryuta.models.session import UserSession
from repositoryuta.services import app_auth_service, token_service


def _make_app(
    session, *, client_id="uta-signature", secret="s3cr3t", is_active=True
) -> Application:
    app = Application(
        name="UTA Signature",
        client_id=client_id,
        client_secret_hash=token_service.hash_token(secret),
        is_active=is_active,
    )
    session.add(app)
    session.flush()
    return app


def _make_local_user(session, *, email="juan@uta.edu.ec", password="OldPass1", is_active=True):
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


# ── authenticate_application ─────────────────────────────────────────────────


def test_authenticate_application_invalid_client_id_fails(sqlite_session) -> None:
    result = app_auth_service.authenticate_application(
        sqlite_session, "unknown", "secret", "127.0.0.1", "pytest"
    )
    assert result.success is False
    assert result.message == "Invalid client credentials"


def test_authenticate_application_wrong_secret_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")

    result = app_auth_service.authenticate_application(
        sqlite_session, "uta-signature", "wrong", "127.0.0.1", "pytest"
    )
    assert result.success is False


def test_authenticate_application_inactive_client_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct", is_active=False)

    result = app_auth_service.authenticate_application(
        sqlite_session, "uta-signature", "correct", "127.0.0.1", "pytest"
    )
    assert result.success is False


def test_authenticate_application_success_issues_app_token(sqlite_session) -> None:
    app = _make_app(sqlite_session, client_id="uta-signature", secret="correct")

    result = app_auth_service.authenticate_application(
        sqlite_session, "uta-signature", "correct", "127.0.0.1", "pytest"
    )

    assert result.success is True
    assert result.application_id == app.id
    payload = decode_token(result.access_token)
    assert payload["client_id"] == "uta-signature"
    assert payload["token_use"] == "app"
    assert payload[CLAIM_ROLE] == ["Application"]
    assert sqlite_session.query(LegacyAuthLog).filter_by(auth_result="Success").count() == 1


def test_authenticate_application_uses_configured_client_roles(sqlite_session, monkeypatch) -> None:
    from repositoryuta.config import get_settings

    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    settings = get_settings()
    monkeypatch.setitem(settings.app_auth.client_roles, "uta-signature", ["CustomRole"])

    result = app_auth_service.authenticate_application(
        sqlite_session, "uta-signature", "correct", "127.0.0.1", "pytest"
    )

    payload = decode_token(result.access_token)
    assert payload[CLAIM_ROLE] == ["CustomRole"]


# ── authenticate_user_legacy ─────────────────────────────────────────────────


def test_authenticate_user_legacy_invalid_application_fails(sqlite_session) -> None:
    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "unknown", "secret", "juan@uta.edu.ec", "pw", False, None, None
    )
    assert result.success is False
    assert result.message == "Invalid application"


def test_authenticate_user_legacy_wrong_app_secret_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "wrong", "juan@uta.edu.ec", "pw", False, None, None
    )
    assert result.success is False
    assert result.message == "Invalid application credentials"


def test_authenticate_user_legacy_unknown_user_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "nadie@uta.edu.ec", "pw", False, None, None
    )
    assert result.success is False
    assert result.message == "User not found"


def test_authenticate_user_legacy_inactive_user_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    _make_local_user(sqlite_session, is_active=False)

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "juan@uta.edu.ec", "OldPass1", False, None, None
    )
    assert result.success is False
    assert result.message == "User is inactive"


def test_authenticate_user_legacy_local_user_without_credentials_fails(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "juan@uta.edu.ec", "pw", False, None, None
    )
    assert result.success is False
    assert result.message == "No local credentials found"


def test_authenticate_user_legacy_azuread_user_rejected(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    user = User(id=uuid4(), email="azure@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "azure@uta.edu.ec", "pw", False, None, None
    )
    assert result.success is False
    assert "Azure AD" in result.message


def test_authenticate_user_legacy_wrong_password_locks_after_max_attempts(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    user = _make_local_user(sqlite_session)
    credentials = sqlite_session.get(LocalUserCredential, user.id)

    for _ in range(5):
        result = app_auth_service.authenticate_user_legacy(
            sqlite_session,
            "uta-signature",
            "correct",
            "juan@uta.edu.ec",
            "wrong",
            False,
            None,
            None,
        )
        assert result.success is False

    sqlite_session.refresh(credentials)
    assert credentials.is_locked is True

    locked_result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "juan@uta.edu.ec", "OldPass1", False, None, None
    )
    assert locked_result.success is False
    assert locked_result.message == "Account is locked"


def test_authenticate_user_legacy_success_without_permissions(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    _make_local_user(sqlite_session)

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "juan@uta.edu.ec", "OldPass1", False, None, None
    )

    assert result.success is True
    assert result.roles is None
    assert result.permissions is None
    assert sqlite_session.query(LegacyAuthLog).filter_by(auth_result="Success").count() == 1


def test_authenticate_user_legacy_success_with_permissions(sqlite_session) -> None:
    _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    user = _make_local_user(sqlite_session)
    role = Role(name="R_RH")
    permission = Permission(name="Ver", module="Empleados", action="Read")
    sqlite_session.add_all([role, permission])
    sqlite_session.flush()
    sqlite_session.add_all(
        [
            UserRole(user_id=user.id, role_id=role.id),
            RolePermission(role_id=role.id, permission_id=permission.id),
        ]
    )
    sqlite_session.flush()

    result = app_auth_service.authenticate_user_legacy(
        sqlite_session, "uta-signature", "correct", "juan@uta.edu.ec", "OldPass1", True, None, None
    )

    assert result.success is True
    assert result.roles[0].name == "R_RH"
    assert result.permissions[0].module == "Empleados"


# ── validate_token ────────────────────────────────────────────────────────────


def test_validate_token_not_a_guid_is_invalid(sqlite_session) -> None:
    result = app_auth_service.validate_token(sqlite_session, "not-a-guid", None)
    assert result.is_valid is False


def test_validate_token_unknown_session_is_invalid(sqlite_session) -> None:
    result = app_auth_service.validate_token(sqlite_session, str(uuid4()), None)
    assert result.is_valid is False


def test_validate_token_active_session_is_valid(sqlite_session) -> None:
    session_row = UserSession(
        session_id=uuid4(),
        user_id=uuid4(),
        access_token="a",
        refresh_token="r",
        expires_at=datetime.now() + timedelta(hours=1),
        is_active=True,
    )
    sqlite_session.add(session_row)
    sqlite_session.flush()

    result = app_auth_service.validate_token(sqlite_session, str(session_row.session_id), None)

    assert result.is_valid is True
    assert result.user_id == session_row.user_id


# ── get_application_stats ─────────────────────────────────────────────────────


def test_get_application_stats_unknown_client_returns_none(sqlite_session) -> None:
    assert app_auth_service.get_application_stats(sqlite_session, "unknown") is None


def test_get_application_stats_counts_attempts(sqlite_session) -> None:
    app = _make_app(sqlite_session, client_id="uta-signature", secret="correct")
    sqlite_session.add_all(
        [
            LegacyAuthLog(
                application_id=app.id,
                user_email="a@b.com",
                auth_result="Success",
                created_at=datetime.now(),
            ),
            LegacyAuthLog(
                application_id=app.id,
                user_email="a@b.com",
                auth_result="Failed",
                created_at=datetime.now(),
            ),
        ]
    )
    sqlite_session.flush()

    stats = app_auth_service.get_application_stats(sqlite_session, "uta-signature")

    assert stats.total_auth_attempts == 2
    assert stats.successful_auths == 1
    assert stats.auths_last_7_days == 2
