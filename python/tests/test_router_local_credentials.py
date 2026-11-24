from datetime import datetime
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.identity import LocalUserCredential


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_local_credential(client, sqlite_session) -> None:
    user_id = uuid4()
    sqlite_session.add(
        LocalUserCredential(
            user_id=user_id, password_hash="hash", password_created_at=datetime.now()
        )
    )
    sqlite_session.flush()

    listed = client.get("/api/local-credentials", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/local-credentials/{user_id}", headers=_admin_header())
    assert got.status_code == 200
    assert got.json()["data"]["passwordHash"] == "hash"


def test_get_unknown_local_credential_returns_404(client) -> None:
    response = client.get(f"/api/local-credentials/{uuid4()}", headers=_admin_header())
    assert response.status_code == 404


def test_create_update_and_delete_local_credential(client) -> None:
    user_id = uuid4()
    created = client.post(
        "/api/local-credentials",
        json={"userId": str(user_id), "passwordHash": "hash"},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    updated = client.put(
        f"/api/local-credentials/{user_id}", json={"isLocked": True}, headers=_admin_header()
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["isLocked"] is True

    deleted = client.delete(f"/api/local-credentials/{user_id}", headers=_admin_header())
    assert deleted.status_code == 200

    missing = client.get(f"/api/local-credentials/{user_id}", headers=_admin_header())
    assert missing.status_code == 404
