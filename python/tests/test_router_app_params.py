from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.app_param import AppParam


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_app_param(client, sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="Jwt:AccessTokenLifetimeMinutes", value="60"))
    sqlite_session.flush()

    listed = client.get("/api/app-params", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(
        "/api/app-params/Jwt:AccessTokenLifetimeMinutes", headers=_admin_header()
    )
    assert got.status_code == 200
    assert got.json()["data"]["value"] == "60"


def test_get_unknown_app_param_returns_404(client) -> None:
    response = client.get("/api/app-params/DoesNotExist", headers=_admin_header())
    assert response.status_code == 404


def test_create_update_and_delete_app_param(client) -> None:
    created = client.post(
        "/api/app-params",
        json={"nemonic": "Feature:X", "value": "true"},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    updated = client.put(
        "/api/app-params/Feature:X", json={"value": "false"}, headers=_admin_header()
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["value"] == "false"

    deleted = client.delete("/api/app-params/Feature:X", headers=_admin_header())
    assert deleted.status_code == 200

    missing = client.get("/api/app-params/Feature:X", headers=_admin_header())
    assert missing.status_code == 404
