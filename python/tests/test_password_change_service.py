from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.password import hash_password
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.repositories.security_token_repository import SecurityTokenRepository
from repositoryuta.services import password_change_service as svc
from repositoryuta.services import token_service


def _make_local_user(session, *, password="OldPass1", is_active=True, user_type="Local"):
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type=user_type, is_active=is_active)
    session.add(user)
    session.flush()
    if user_type.lower() == "local":
        session.add(
            LocalUserCredential(
                user_id=user.id,
                password_hash=hash_password(password),
                password_created_at=datetime.now(),
            )
        )
        session.flush()
    return user


# ── change_password ──────────────────────────────────────────────────────────


def test_change_password_success(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password(sqlite_session, user.id, "OldPass1", "NewPass2")

    assert result.success is True
    cred = sqlite_session.get(LocalUserCredential, user.id)
    from repositoryuta.core.security.password import verify_password

    assert verify_password("NewPass2", cred.password_hash)
    assert cred.password_expires_at > datetime.now() + timedelta(days=89)


def test_change_password_rejects_wrong_current_password(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password(sqlite_session, user.id, "wrong", "NewPass2")

    assert result.success is False
    assert result.message == "La contraseña actual es incorrecta"


def test_change_password_rejects_same_as_current(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password(sqlite_session, user.id, "OldPass1", "OldPass1")

    assert result.success is False
    assert "igual a la actual" in result.message


def test_change_password_rejects_weak_password(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password(sqlite_session, user.id, "OldPass1", "weak")

    assert result.success is False
    assert "no cumple los requisitos" in result.message


def test_change_password_rejects_non_local_user(sqlite_session) -> None:
    user = _make_local_user(sqlite_session, user_type="AzureAD")

    result = svc.change_password(sqlite_session, user.id, "x", "NewPass2")

    assert result.success is False
    assert "AD/Azure" in result.message


def test_change_password_rejects_unknown_user(sqlite_session) -> None:
    result = svc.change_password(sqlite_session, uuid4(), "x", "NewPass2")

    assert result.success is False
    assert result.message == "Usuario no encontrado o inactivo"


def test_change_password_rejects_local_user_without_credential(sqlite_session) -> None:
    user = User(id=uuid4(), email="sin-cred@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = svc.change_password(sqlite_session, user.id, "x", "NewPass2")

    assert result.success is False
    assert result.message == "El usuario no tiene credenciales locales"


# ── request_password_change_2fa ──────────────────────────────────────────────


def test_request_2fa_returns_otp_only_in_development(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    prod_result = svc.request_password_change_2fa(sqlite_session, user.id, is_development=False)
    assert prod_result.success is True
    assert prod_result.otp_code_dev is None

    dev_result = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)
    assert dev_result.otp_code_dev is not None
    assert len(dev_result.otp_code_dev) == 6


def test_request_2fa_invalidates_previous_pending_otp(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    first = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)
    svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)

    tokens = SecurityTokenRepository(sqlite_session)
    stale = tokens.find_valid(
        user.id, svc.OTP_TOKEN_TYPE, token_service.hash_token(first.otp_code_dev)
    )
    assert stale is None


def test_request_2fa_rejects_unknown_or_inactive_user(sqlite_session) -> None:
    result = svc.request_password_change_2fa(sqlite_session, uuid4())

    assert result.success is False
    assert result.message == "Usuario no encontrado o inactivo"


def test_request_2fa_allows_non_local_user_without_checking_credential(sqlite_session) -> None:
    user = _make_local_user(sqlite_session, user_type="AzureAD")

    result = svc.request_password_change_2fa(sqlite_session, user.id)

    assert result.success is True


def test_request_2fa_rejects_local_user_without_credential(sqlite_session) -> None:
    user = User(id=uuid4(), email="sin-cred@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = svc.request_password_change_2fa(sqlite_session, user.id)

    assert result.success is False
    assert result.message == "El usuario no tiene credenciales locales"


# ── change_password_with_2fa ─────────────────────────────────────────────────


def test_change_password_with_2fa_success(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    otp = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)

    result = svc.change_password_with_2fa(
        sqlite_session, user.id, "OldPass1", "NewPass2", otp.otp_code_dev
    )

    assert result.success is True
    tokens = SecurityTokenRepository(sqlite_session)
    assert (
        tokens.find_valid(user.id, svc.OTP_TOKEN_TYPE, token_service.hash_token(otp.otp_code_dev))
        is None
    )


def test_change_password_with_2fa_rejects_invalid_user(sqlite_session) -> None:
    user = _make_local_user(sqlite_session, user_type="AzureAD")

    result = svc.change_password_with_2fa(sqlite_session, user.id, "x", "NewPass2", "000000")

    assert result.success is False
    assert result.message == "Usuario no válido para esta operación"


def test_change_password_with_2fa_rejects_local_user_without_credential(sqlite_session) -> None:
    user = User(id=uuid4(), email="sin-cred2@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    result = svc.change_password_with_2fa(sqlite_session, user.id, "x", "NewPass2", "000000")

    assert result.success is False
    assert result.message == "El usuario no tiene credenciales locales"


def test_change_password_with_2fa_rejects_wrong_current_password(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password_with_2fa(
        sqlite_session, user.id, "wrong", "NewPass2", "000000"
    )

    assert result.success is False
    assert result.message == "La contraseña actual es incorrecta"


def test_change_password_with_2fa_rejects_same_as_current(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    otp = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)

    result = svc.change_password_with_2fa(
        sqlite_session, user.id, "OldPass1", "OldPass1", otp.otp_code_dev
    )

    assert result.success is False
    assert "igual a la actual" in result.message


def test_change_password_with_2fa_rejects_invalid_otp(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    result = svc.change_password_with_2fa(
        sqlite_session, user.id, "OldPass1", "NewPass2", "000000"
    )

    assert result.success is False
    assert "OTP" in result.message


def test_change_password_with_2fa_checks_complexity_before_equality(sqlite_session) -> None:
    """Orden de checks distinto a change_password(): aqui complejidad va antes
    que igual-a-la-actual (inconsistencia real del .NET, preservada)."""
    user = _make_local_user(sqlite_session)
    otp = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)

    result = svc.change_password_with_2fa(
        sqlite_session, user.id, "OldPass1", "weak", otp.otp_code_dev
    )

    assert result.success is False
    assert "no cumple los requisitos" in result.message


# ── verify_and_consume_password_otp ──────────────────────────────────────────


def test_verify_and_consume_otp(sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    otp = svc.request_password_change_2fa(sqlite_session, user.id, is_development=True)

    result = svc.verify_and_consume_password_otp(sqlite_session, user.id, otp.otp_code_dev)
    assert result.success is True

    # Ya consumido: una segunda verificacion con el mismo codigo debe fallar.
    second = svc.verify_and_consume_password_otp(sqlite_session, user.id, otp.otp_code_dev)
    assert second.success is False
