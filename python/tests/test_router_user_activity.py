from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.identity import UserActivityLog


def _user_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "juan@uta.edu.ec", ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_user_activity_no_admin_role_required(client, sqlite_session) -> None:
    entry = UserActivityLog(user_id=uuid4(), activity="Login")
    sqlite_session.add(entry)
    sqlite_session.flush()

    listed = client.get("/api/user-activity", headers=_user_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/user-activity/{entry.id}", headers=_user_header())
    assert got.status_code == 200
    assert got.json()["data"]["activity"] == "Login"


def test_get_unknown_user_activity_returns_404(client) -> None:
    response = client.get("/api/user-activity/999", headers=_user_header())
    assert response.status_code == 404


def test_create_and_update_user_activity(client) -> None:
    user_id = uuid4()
    created = client.post(
        "/api/user-activity",
        json={"userId": str(user_id), "activity": "Login"},
        headers=_user_header(),
    )
    assert created.status_code == 200
    activity_id = created.json()["data"]["id"]

    updated = client.put(
        f"/api/user-activity/{activity_id}",
        json={"activityDetails": "Desde VPN"},
        headers=_user_header(),
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["activityDetails"] == "Desde VPN"


def test_no_delete_endpoint(client) -> None:
    assert client.delete("/api/user-activity/1", headers=_user_header()).status_code == 405
