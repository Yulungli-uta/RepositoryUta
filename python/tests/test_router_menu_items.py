from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.rbac import MenuItem


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_response_is_not_wrapped_in_apiresponse(client, sqlite_session) -> None:
    sqlite_session.add(MenuItem(name="RRHH", order=1))
    sqlite_session.flush()

    response = client.get("/api/menu-items", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()
    assert "success" not in body
    assert body["totalCount"] == 1
    assert body["items"][0]["name"] == "RRHH"


def test_get_unknown_menu_item_returns_404(client) -> None:
    response = client.get("/api/menu-items/999", headers=_admin_header())
    assert response.status_code == 404


def test_create_update_and_delete_menu_item(client, sqlite_session) -> None:
    created = client.post(
        "/api/menu-items", json={"name": "RRHH", "order": 1}, headers=_admin_header()
    )
    assert created.status_code == 200
    item_id = created.json()["data"]["id"]

    updated = client.put(
        f"/api/menu-items/{item_id}", json={"name": "Recursos Humanos"}, headers=_admin_header()
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["name"] == "Recursos Humanos"

    deleted = client.delete(f"/api/menu-items/{item_id}", headers=_admin_header())
    assert deleted.status_code == 200

    entity = sqlite_session.get(MenuItem, item_id)
    sqlite_session.refresh(entity)
    # MenuItem SI implementa ISoftDeletable en .NET: el delete generico marca
    # is_deleted, no borra la fila.
    assert entity.is_deleted is True

    missing = client.get(f"/api/menu-items/{item_id}", headers=_admin_header())
    assert missing.status_code == 404
