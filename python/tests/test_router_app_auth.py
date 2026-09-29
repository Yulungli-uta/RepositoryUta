from datetime import datetime
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.core.security.password import hash_password
from repositoryuta.models.application import Application
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.services import token_service


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def _make_app(session, *, client_id="uta-signature", secret="correct") -> Application:
    app = Application(
        name="UTA Signature",
        client_id=client_id,
        client_secret_hash=token_service.hash_token(secret),
        is_active=True,
    )
    session.add(app)
    session.flush()
    return app


def test_get_application_token_success(client, sqlite_session) -> None:
    _make_app(sqlite_session)

    response = client.post(
        "/api/app-auth/token", json={"clientId": "uta-signature", "clientSecret": "correct"}
    )

    assert response.status_code == 200
    assert response.json()["data"]["accessToken"]


def test_get_application_token_invalid_credentials_returns_401(client, sqlite_session) -> None:
    _make_app(sqlite_session)

    response = client.post(
        "/api/app-auth/token", json={"clientId": "uta-signature", "clientSecret": "wrong"}
    )

    assert response.status_code == 401


def test_legacy_login_success(client, sqlite_session) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()
    sqlite_session.add(
        LocalUserCredential(
            user_id=user.id,
            password_hash=hash_password("OldPass1"),
            password_created_at=datetime.now(),
        )
    )
    sqlite_session.flush()

    response = client.post(
        "/api/app-auth/legacy-login",
        json={
            "clientId": "uta-signature",
            "clientSecret": "correct",
            "userEmail": "juan@uta.edu.ec",
            "password": "OldPass1",
        },
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "juan@uta.edu.ec"


def test_legacy_login_wrong_password_returns_401(client, sqlite_session) -> None:
    _make_app(sqlite_session)
    user = User(id=uuid4(), email="juan@uta.edu.ec", user_type="Local", is_active=True)
    sqlite_session.add(user)
    sqlite_session.flush()
    sqlite_session.add(
        LocalUserCredential(
            user_id=user.id,
            password_hash=hash_password("OldPass1"),
            password_created_at=datetime.now(),
        )
    )
    sqlite_session.flush()

    response = client.post(
        "/api/app-auth/legacy-login",
        json={
            "clientId": "uta-signature",
            "clientSecret": "correct",
            "userEmail": "juan@uta.edu.ec",
            "password": "wrong",
        },
    )

    assert response.status_code == 401


def test_validate_token_always_returns_200(client) -> None:
    response = client.post("/api/app-auth/validate-token", json={"token": "not-a-guid"})

    assert response.status_code == 200
    assert response.json()["data"]["isValid"] is False


def test_get_application_stats_requires_authentication(client) -> None:
    response = client.get("/api/app-auth/stats/uta-signature")
    assert response.status_code == 401


def test_get_application_stats_unknown_client_returns_404(client) -> None:
    response = client.get("/api/app-auth/stats/unknown", headers=_admin_header())
    assert response.status_code == 404


def test_get_application_stats_success(client, sqlite_session) -> None:
    _make_app(sqlite_session)

    response = client.get("/api/app-auth/stats/uta-signature", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["clientId"] == "uta-signature"
