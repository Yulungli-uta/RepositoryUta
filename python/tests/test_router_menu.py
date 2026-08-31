from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.identity import User
from repositoryuta.models.rbac import MenuItem, Role, RoleMenuItem, UserRole


def _auth_header(user_id, email="juan@uta.edu.ec", roles=None) -> dict[str, str]:
    token = create_user_token(str(user_id), email, roles or [])
    return {"Authorization": f"Bearer {token}"}


def test_get_menu_for_authenticated_user(client, sqlite_session) -> None:
    user = User(id=uuid4(), email="juan@uta.edu.ec")
    role = Role(name="R_EMPLOYEE")
    sqlite_session.add_all([user, role])
    sqlite_session.flush()
    item = MenuItem(name="Mis Vacaciones", order=1)
    sqlite_session.add(item)
    sqlite_session.flush()
    sqlite_session.add_all(
        [
            UserRole(user_id=user.id, role_id=role.id),
            RoleMenuItem(role_id=role.id, menu_item_id=item.id),
        ]
    )
    sqlite_session.flush()

    response = client.get("/api/menu/user", headers=_auth_header(user.id))

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["data"][0]["name"] == "Mis Vacaciones"


def test_get_menu_requires_authentication(client) -> None:
    response = client.get("/api/menu/user")

    assert response.status_code == 401


def test_get_menu_rejects_malformed_authorization_header(client) -> None:
    response = client.get("/api/menu/user", headers={"Authorization": "NotBearer whatever"})

    assert response.status_code == 401


def test_get_menu_rejects_garbage_token(client) -> None:
    response = client.get("/api/menu/user", headers={"Authorization": "Bearer not-a-jwt"})

    assert response.status_code == 401


def test_get_menu_rejects_token_with_non_uuid_subject(client) -> None:
    from repositoryuta.core.security.jwt import create_app_token

    token = create_app_token("token-1", "some-client", [], 60)

    response = client.get("/api/menu/user", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
