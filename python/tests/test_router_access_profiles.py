from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.access_profile import AccessProfile


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_response_is_not_wrapped_in_apiresponse(client, sqlite_session) -> None:
    sqlite_session.add(AccessProfile(name="Directora Administrativa"))
    sqlite_session.flush()

    response = client.get("/api/access-profiles", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()
    assert "success" not in body
    assert body["totalCount"] == 1
    assert body["items"][0]["name"] == "Directora Administrativa"


def test_get_unknown_access_profile_returns_404(client) -> None:
    response = client.get("/api/access-profiles/999", headers=_admin_header())
    assert response.status_code == 404


def test_create_update_and_delete_access_profile(client, sqlite_session) -> None:
    created = client.post(
        "/api/access-profiles",
        json={"name": "Perfil RH", "description": "Acceso RH"},
        headers=_admin_header(),
    )
    assert created.status_code == 200
    profile_id = created.json()["data"]["id"]

    updated = client.put(
        f"/api/access-profiles/{profile_id}",
        json={"description": "Acceso RH actualizado", "isActive": True},
        headers=_admin_header(),
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["description"] == "Acceso RH actualizado"

    deleted = client.delete(f"/api/access-profiles/{profile_id}", headers=_admin_header())
    assert deleted.status_code == 200

    entity = sqlite_session.get(AccessProfile, profile_id)
    sqlite_session.refresh(entity)
    # Soft-delete manual: sigue existiendo la fila, pero inactiva y marcada.
    assert entity.is_deleted is True
    assert entity.is_active is False


def test_update_unknown_access_profile_returns_404(client) -> None:
    response = client.put(
        "/api/access-profiles/999", json={"description": "x"}, headers=_admin_header()
    )
    assert response.status_code == 404


def test_delete_unknown_access_profile_returns_404(client) -> None:
    response = client.delete("/api/access-profiles/999", headers=_admin_header())
    assert response.status_code == 404
