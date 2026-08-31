from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.audit import HRSyncLog


def _user_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "juan@uta.edu.ec", ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_hr_sync_log(client, sqlite_session) -> None:
    entry = HRSyncLog(records_processed=7)
    sqlite_session.add(entry)
    sqlite_session.flush()

    listed = client.get("/api/hr-sync-log", headers=_user_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/hr-sync-log/{entry.id}", headers=_user_header())
    assert got.status_code == 200
    assert got.json()["data"]["recordsProcessed"] == 7


def test_get_unknown_hr_sync_log_returns_404(client) -> None:
    response = client.get("/api/hr-sync-log/999", headers=_user_header())
    assert response.status_code == 404


def test_create_and_update_hr_sync_log(client) -> None:
    created = client.post(
        "/api/hr-sync-log", json={"recordsProcessed": 3}, headers=_user_header()
    )
    assert created.status_code == 200
    log_id = created.json()["data"]["id"]

    updated = client.put(f"/api/hr-sync-log/{log_id}", json={"newUsers": 2}, headers=_user_header())
    assert updated.status_code == 200
    assert updated.json()["data"]["newUsers"] == 2


def test_no_delete_endpoint(client) -> None:
    assert client.delete("/api/hr-sync-log/1", headers=_user_header()).status_code == 405
