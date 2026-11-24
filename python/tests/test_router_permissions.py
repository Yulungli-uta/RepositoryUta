from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_permissions_requires_admin(client) -> None:
    response = client.get("/api/permissions")

    assert response.status_code == 401


def test_crud_lifecycle(client, sqlite_session) -> None:
    created = client.post(
        "/api/permissions",
        json={"name": "Ver Contratos", "module": "Contracts", "action": "Read"},
        headers=_admin_header(),
    )
    assert created.status_code == 200
    permission_id = created.json()["data"]["id"]

    listed = client.get("/api/permissions", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    updated = client.put(
        f"/api/permissions/{permission_id}",
        json={"description": "Permite ver contratos"},
        headers=_admin_header(),
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["description"] == "Permite ver contratos"
    assert updated.json()["data"]["module"] == "Contracts"

    deleted = client.delete(f"/api/permissions/{permission_id}", headers=_admin_header())
    assert deleted.status_code == 200

    # Permission implementa SoftDeleteMixin: tras "eliminar" ya no aparece.
    sqlite_session.expire_all()
    missing = client.get(f"/api/permissions/{permission_id}", headers=_admin_header())
    assert missing.status_code == 404


def test_get_unknown_permission_returns_404(client) -> None:
    response = client.get("/api/permissions/999999", headers=_admin_header())

    assert response.status_code == 404


def test_update_unknown_permission_returns_404(client) -> None:
    response = client.put(
        "/api/permissions/999999", json={"description": "x"}, headers=_admin_header()
    )

    assert response.status_code == 404


def test_delete_unknown_permission_returns_404(client) -> None:
    response = client.delete("/api/permissions/999999", headers=_admin_header())

    assert response.status_code == 404
