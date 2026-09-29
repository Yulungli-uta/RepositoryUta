from datetime import datetime
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.core.security.password import hash_password
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.services import password_change_service


def _auth_header(user_id, email="juan@uta.edu.ec", roles=None) -> dict[str, str]:
    token = create_user_token(str(user_id), email, roles or [])
    return {"Authorization": f"Bearer {token}"}


def _make_local_user(session, *, email="juan@uta.edu.ec", password="OldPass1"):
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


# ── login / refresh / logout ─────────────────────────────────────────────────


def test_login_success(client, sqlite_session) -> None:
    _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/login", json={"email": "juan@uta.edu.ec", "password": "OldPass1"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"]["accessToken"]
    assert body["data"]["refreshToken"]


def test_login_wrong_credentials_returns_401(client, sqlite_session) -> None:
    _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/login", json={"email": "juan@uta.edu.ec", "password": "wrong"}
    )

    assert response.status_code == 401


def test_login_is_rate_limited_after_six_attempts(client, sqlite_session) -> None:
    for _ in range(6):
        client.post("/api/auth/login", json={"email": "nadie@uta.edu.ec", "password": "x"})

    response = client.post("/api/auth/login", json={"email": "nadie@uta.edu.ec", "password": "x"})

    assert response.status_code == 429


def test_refresh_and_logout_flow(client, sqlite_session) -> None:
    _make_local_user(sqlite_session)
    login = client.post(
        "/api/auth/login", json={"email": "juan@uta.edu.ec", "password": "OldPass1"}
    )
    refresh_token = login.json()["data"]["refreshToken"]

    refreshed = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200
    new_refresh_token = refreshed.json()["data"]["refreshToken"]

    # El token viejo ya fue rotado: reusarlo no debe funcionar.
    stale = client.post("/api/auth/refresh", json={"refresh_token": refresh_token})
    assert stale.status_code == 401

    logout = client.post("/api/auth/logout", json={"refresh_token": new_refresh_token})
    assert logout.status_code == 200
    assert logout.json()["data"] is True


def test_logout_requires_non_empty_refresh_token(client) -> None:
    response = client.post("/api/auth/logout", json={"refresh_token": "  "})

    assert response.status_code == 400


# ── me ───────────────────────────────────────────────────────────────────────


def test_me_returns_profile_for_authenticated_user(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.get("/api/auth/me", headers=_auth_header(user.id, user.email))

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "juan@uta.edu.ec"


def test_me_requires_authentication(client) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_404_for_deleted_user_with_valid_token(client) -> None:
    response = client.get("/api/auth/me", headers=_auth_header(uuid4()))

    assert response.status_code == 404


# ── validate-token ───────────────────────────────────────────────────────────


def test_validate_token_endpoint(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)
    token = create_user_token(str(user.id), user.email, [])

    response = client.post("/api/auth/validate-token", json={"token": token})

    assert response.status_code == 200
    assert response.json()["data"]["isValid"] is True


def test_validate_token_requires_token_field(client) -> None:
    response = client.post("/api/auth/validate-token", json={"token": ""})

    assert response.status_code == 400


# ── change-password ──────────────────────────────────────────────────────────


def test_change_password_success(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "OldPass1", "new_password": "NewPass2"},
        headers=_auth_header(user.id, user.email),
    )

    assert response.status_code == 200
    assert response.json()["data"]["success"] is True


def test_change_password_rejects_blank_current_password(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "  ", "new_password": "NewPass2"},
        headers=_auth_header(user.id, user.email),
    )

    assert response.status_code == 400


def test_change_password_wrong_current_returns_400(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "wrong", "new_password": "NewPass2"},
        headers=_auth_header(user.id, user.email),
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "La contraseña actual es incorrecta"


def test_change_password_for_azuread_user_returns_clear_message(client, sqlite_session) -> None:
    user = User(id=uuid4(), email="azure@uta.edu.ec", user_type="AzureAD", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()

    response = client.post(
        "/api/auth/change-password",
        json={"current_password": "x", "new_password": "NewPass2"},
        headers=_auth_header(user.id, user.email),
    )

    assert response.status_code == 400
    assert "AD/Azure" in response.json()["detail"]


# ── 2FA ──────────────────────────────────────────────────────────────────────


def test_request_and_apply_2fa_password_change(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    otp_response = client.post(
        "/api/auth/request-password-change-2fa", headers=_auth_header(user.id, user.email)
    )
    assert otp_response.status_code == 200
    # app_env=test no es "development": no debe filtrar el codigo en la respuesta HTTP.
    assert otp_response.json()["data"]["otpCodeDev"] is None

    otp_code = password_change_service.request_password_change_2fa(
        sqlite_session, user.id, is_development=True
    ).otp_code_dev

    change_response = client.post(
        "/api/auth/change-password-2fa",
        json={"current_password": "OldPass1", "new_password": "NewPass2", "otp_code": otp_code},
        headers=_auth_header(user.id, user.email),
    )

    assert change_response.status_code == 200
    assert change_response.json()["data"]["success"] is True


def test_change_password_2fa_requires_otp_and_new_password(client, sqlite_session) -> None:
    user = _make_local_user(sqlite_session)

    response = client.post(
        "/api/auth/change-password-2fa",
        json={"current_password": "OldPass1", "new_password": "  ", "otp_code": "  "},
        headers=_auth_header(user.id, user.email),
    )

    assert response.status_code == 400


# ── password-change-method ───────────────────────────────────────────────────


def test_get_password_change_method(client) -> None:
    response = client.get("/api/auth/password-change-method")

    assert response.status_code == 200
    assert response.json()["data"]["method"] == "LocalAd"
