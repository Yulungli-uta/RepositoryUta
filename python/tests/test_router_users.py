from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import AuditLog
from repositoryuta.models.identity import (
    LocalUserCredential,
    SecurityToken,
    User,
    UserActivityLog,
    UserEmployee,
)
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.models.session import UserSession


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_create_user_requires_admin_role(client) -> None:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])

    response = client.post(
        "/api/users",
        json={"email": "nuevo@uta.edu.ec", "hr_employee_id": 42},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


def test_create_user_requires_authentication(client) -> None:
    response = client.post(
        "/api/users", json={"email": "nuevo@uta.edu.ec", "hr_employee_id": 42}
    )

    assert response.status_code == 401


def test_create_user_success_as_admin(client) -> None:
    response = client.post(
        "/api/users",
        json={"email": "nuevo@uta.edu.ec", "hr_employee_id": 42, "display_name": "Nuevo"},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["user"]["email"] == "nuevo@uta.edu.ec"
    assert body["userEmployee"]["hrEmployeeId"] == 42


def test_create_azuread_user_without_hr_employee_id_is_rejected(client) -> None:
    response = client.post(
        "/api/users",
        json={"email": "azure@uta.edu.ec", "hr_employee_id": 0, "user_type": "AzureAD"},
        headers=_admin_header(),
    )

    assert response.status_code == 400


def test_create_user_duplicate_email_returns_409(client, sqlite_session) -> None:
    from uuid import uuid4 as make_uuid

    from repositoryuta.models.identity import User

    sqlite_session.add(User(id=make_uuid(), email="repetido@uta.edu.ec"))
    sqlite_session.flush()

    response = client.post(
        "/api/users",
        json={"email": "repetido@uta.edu.ec", "hr_employee_id": 1},
        headers=_admin_header(),
    )

    assert response.status_code == 409


def test_create_user_logs_audit(client, sqlite_session) -> None:
    response = client.post(
        "/api/users",
        json={"email": "auditado@uta.edu.ec", "hr_employee_id": 55},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert sqlite_session.query(AuditLog).filter_by(action="UserCreated").count() == 1


def test_list_response_is_wrapped_in_apiresponse(client, sqlite_session) -> None:
    sqlite_session.add(User(id=uuid4(), email="juan@uta.edu.ec"))
    sqlite_session.flush()

    response = client.get("/api/users", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["totalCount"] == 1


def test_get_unknown_user_returns_404(client) -> None:
    response = client.get(f"/api/users/{uuid4()}", headers=_admin_header())
    assert response.status_code == 404


def test_update_user_logs_before_after_audit(client, sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(User(id=user_id, email="juan@uta.edu.ec", display_name="Juan"))
    sqlite_session.flush()

    response = client.put(
        f"/api/users/{user_id}", json={"displayName": "Juan Perez"}, headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["displayName"] == "Juan Perez"
    audit = sqlite_session.query(AuditLog).filter_by(action="UserUpdated").one()
    assert '"displayName": "Juan"' in audit.old_values
    assert '"displayName": "Juan Perez"' in audit.new_values


def test_update_unknown_user_returns_404(client) -> None:
    response = client.put(
        f"/api/users/{uuid4()}", json={"displayName": "X"}, headers=_admin_header()
    )
    assert response.status_code == 404


def test_delete_user_cascades_related_tables_and_logs_audit(client, sqlite_session) -> None:
    user_id = uuid4()
    role = Role(name="R_RH")
    sqlite_session.add_all([User(id=user_id, email="juan@uta.edu.ec"), role])
    sqlite_session.flush()
    sqlite_session.add_all(
        [
            UserEmployee(user_id=user_id, employee_email="juan@uta.edu.ec", hr_employee_id=1),
            UserRole(user_id=user_id, role_id=role.id),
            UserSession(
                session_id=uuid4(),
                user_id=user_id,
                access_token="a",
                refresh_token="r",
                expires_at=datetime.now() + timedelta(hours=1),
            ),
            SecurityToken(
                user_id=user_id,
                token_type="PasswordReset",
                token_hash="h",
                expires_at=datetime.now() + timedelta(hours=1),
            ),
            UserActivityLog(user_id=user_id, activity="Login"),
            LocalUserCredential(
                user_id=user_id, password_hash="hash", password_created_at=datetime.now()
            ),
        ]
    )
    sqlite_session.flush()

    response = client.delete(f"/api/users/{user_id}", headers=_admin_header())

    assert response.status_code == 200
    assert sqlite_session.get(User, user_id) is None
    assert sqlite_session.query(UserEmployee).filter_by(user_id=user_id).count() == 0
    assert sqlite_session.query(UserRole).filter_by(user_id=user_id).count() == 0
    assert sqlite_session.query(UserSession).filter_by(user_id=user_id).count() == 0
    assert sqlite_session.query(SecurityToken).filter_by(user_id=user_id).count() == 0
    assert sqlite_session.query(UserActivityLog).filter_by(user_id=user_id).count() == 0
    assert sqlite_session.get(LocalUserCredential, user_id) is None
    assert sqlite_session.query(AuditLog).filter_by(action="UserDeleted").count() == 1


def test_delete_unknown_user_returns_404(client) -> None:
    response = client.delete(f"/api/users/{uuid4()}", headers=_admin_header())
    assert response.status_code == 404


def test_get_paged_users_filters_by_search_and_is_active(client, sqlite_session) -> None:
    sqlite_session.add_all(
        [
            User(id=uuid4(), email="ana@uta.edu.ec", display_name="Ana", is_active=True),
            User(id=uuid4(), email="beto@uta.edu.ec", display_name="Beto", is_active=False),
        ]
    )
    sqlite_session.flush()

    response = client.get(
        "/api/users/paged",
        params={"search": "ana", "isActive": "true"},
        headers=_admin_header(),
    )

    assert response.status_code == 200
    body = response.json()["data"]
    assert body["totalCount"] == 1
    assert body["items"][0]["email"] == "ana@uta.edu.ec"


def test_get_paged_users_no_params_sorts_lastlogin_ascending(client, sqlite_session) -> None:
    """El comentario de ApplyUserSorting en el .NET dice "orden predeterminado:
    ultimo login descendente", pero PagedRequestDto.SortDirection por defecto
    es "asc" (no null) — sin `?sortDirection=desc` explicito en la query,
    `desc = SortDirection != "asc"` da False, y el orden real sin parametros
    es ASCENDENTE. Se replica el comportamiento real del codigo, no lo que
    dice el comentario (regla de fidelidad de Fase 0)."""
    older = User(id=uuid4(), email="viejo@uta.edu.ec", last_login=datetime(2026, 1, 1))
    newer = User(id=uuid4(), email="nuevo@uta.edu.ec", last_login=datetime(2026, 6, 1))
    sqlite_session.add_all([older, newer])
    sqlite_session.flush()

    response = client.get("/api/users/paged", headers=_admin_header())

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert items[0]["email"] == "viejo@uta.edu.ec"


def test_get_paged_users_lastlogin_desc_explicit(client, sqlite_session) -> None:
    older = User(id=uuid4(), email="viejo@uta.edu.ec", last_login=datetime(2026, 1, 1))
    newer = User(id=uuid4(), email="nuevo@uta.edu.ec", last_login=datetime(2026, 6, 1))
    sqlite_session.add_all([older, newer])
    sqlite_session.flush()

    response = client.get(
        "/api/users/paged", params={"sortDirection": "desc"}, headers=_admin_header()
    )

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert items[0]["email"] == "nuevo@uta.edu.ec"


def test_get_paged_users_sort_by_email_ascending_by_default(client, sqlite_session) -> None:
    sqlite_session.add_all(
        [
            User(id=uuid4(), email="zeta@uta.edu.ec"),
            User(id=uuid4(), email="alfa@uta.edu.ec"),
        ]
    )
    sqlite_session.flush()

    response = client.get(
        "/api/users/paged", params={"sortBy": "email"}, headers=_admin_header()
    )

    assert response.status_code == 200
    items = response.json()["data"]["items"]
    assert [item["email"] for item in items] == ["alfa@uta.edu.ec", "zeta@uta.edu.ec"]


def test_get_user_permissions(client, sqlite_session) -> None:
    from repositoryuta.models.rbac import MenuItem, RoleMenuItem
    from repositoryuta.models.views import VwRoleMenuItem, VwUserRole

    user_id = uuid4()
    role = Role(name="R_RH")
    menu_item = MenuItem(name="Empleados", url="/empleados", order=1)
    sqlite_session.add_all([role, menu_item])
    sqlite_session.flush()
    sqlite_session.add_all(
        [
            UserRole(user_id=user_id, role_id=role.id),
            RoleMenuItem(role_id=role.id, menu_item_id=menu_item.id),
            VwUserRole(
                user_id=user_id,
                role_id=role.id,
                email="juan@uta.edu.ec",
                display_name="Juan",
                user_type="Local",
                role_name=role.name,
            ),
            VwRoleMenuItem(
                role_id=role.id,
                menu_item_id=menu_item.id,
                role_name=role.name,
                menu_item_name=menu_item.name,
                url=menu_item.url,
                order=menu_item.order,
                is_visible=True,
                role_specific_visibility=True,
            ),
        ]
    )
    sqlite_session.flush()

    response = client.get(f"/api/users/{user_id}/permissions", headers=_admin_header())

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["roles"][0]["roleName"] == "R_RH"
    assert data["permissions"] == ["/empleados"]
    assert data["menuItems"][0]["menuItemName"] == "Empleados"
