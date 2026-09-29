from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.rbac import MenuItem, Role, RoleMenuItem


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_get_by_role_returns_all_without_pagination(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    sqlite_session.add(role)
    sqlite_session.flush()
    items = [MenuItem(name=f"Item {i}", order=i) for i in range(3)]
    sqlite_session.add_all(items)
    sqlite_session.flush()
    sqlite_session.add_all(
        [RoleMenuItem(role_id=role.id, menu_item_id=item.id) for item in items]
    )
    sqlite_session.flush()

    response = client.get(f"/api/role-menu-items/role/{role.id}", headers=_admin_header())

    assert response.status_code == 200
    assert len(response.json()["data"]) == 3


def test_list_response_is_not_wrapped_in_apiresponse(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    item = MenuItem(name="Item", order=1)
    sqlite_session.add_all([role, item])
    sqlite_session.flush()
    sqlite_session.add(RoleMenuItem(role_id=role.id, menu_item_id=item.id))
    sqlite_session.flush()

    response = client.get("/api/role-menu-items", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()
    assert "success" not in body
    assert body["totalCount"] == 1
    assert body["items"][0]["roleId"] == role.id


def test_get_unknown_role_menu_item_returns_404(client) -> None:
    response = client.get("/api/role-menu-items/1/1", headers=_admin_header())

    assert response.status_code == 404


def test_delete_unknown_role_menu_item_returns_404(client) -> None:
    response = client.delete("/api/role-menu-items/1/1", headers=_admin_header())

    assert response.status_code == 404


def test_create_and_delete_role_menu_item(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    item = MenuItem(name="Item", order=1)
    sqlite_session.add_all([role, item])
    sqlite_session.flush()

    created = client.post(
        "/api/role-menu-items",
        json={"role_id": role.id, "menu_item_id": item.id},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    deleted = client.delete(
        f"/api/role-menu-items/{role.id}/{item.id}", headers=_admin_header()
    )
    assert deleted.status_code == 200

    missing = client.get(
        f"/api/role-menu-items/{role.id}/{item.id}", headers=_admin_header()
    )
    assert missing.status_code == 404
