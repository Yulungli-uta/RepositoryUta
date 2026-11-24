from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.identity import SecurityToken


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_security_token(client, sqlite_session) -> None:
    user_id = uuid4()
    token = SecurityToken(
        user_id=user_id,
        token_type="PasswordReset",
        token_hash="hash",
        expires_at=datetime.now() + timedelta(hours=1),
    )
    sqlite_session.add(token)
    sqlite_session.flush()

    listed = client.get("/api/security-tokens", headers=_admin_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/security-tokens/{token.id}", headers=_admin_header())
    assert got.status_code == 200
    assert got.json()["data"]["tokenType"] == "PasswordReset"


def test_get_unknown_security_token_returns_404(client) -> None:
    response = client.get(f"/api/security-tokens/{uuid4()}", headers=_admin_header())
    assert response.status_code == 404


def test_create_update_and_delete_security_token(client) -> None:
    user_id = uuid4()
    expires_at = (datetime.now() + timedelta(hours=1)).isoformat()

    created = client.post(
        "/api/security-tokens",
        json={
            "userId": str(user_id),
            "tokenType": "PasswordReset",
            "tokenHash": "hash",
            "expiresAt": expires_at,
        },
        headers=_admin_header(),
    )
    assert created.status_code == 200
    token_id = created.json()["data"]["id"]

    updated = client.put(
        f"/api/security-tokens/{token_id}", json={"isUsed": True}, headers=_admin_header()
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["isUsed"] is True

    deleted = client.delete(f"/api/security-tokens/{token_id}", headers=_admin_header())
    assert deleted.status_code == 200

    missing = client.get(f"/api/security-tokens/{token_id}", headers=_admin_header())
    assert missing.status_code == 404
