from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.identity import UserEmployee


def _user_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "juan@uta.edu.ec", ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def test_list_and_get_user_employee_no_admin_role_required(client, sqlite_session) -> None:
    entry = UserEmployee(user_id=uuid4(), employee_email="juan@uta.edu.ec", hr_employee_id=101)
    sqlite_session.add(entry)
    sqlite_session.flush()

    listed = client.get("/api/user-employees", headers=_user_header())
    assert listed.status_code == 200
    assert listed.json()["data"]["totalCount"] == 1

    got = client.get(f"/api/user-employees/{entry.id}", headers=_user_header())
    assert got.status_code == 200
    assert got.json()["data"]["hrEmployeeId"] == 101


def test_get_unknown_user_employee_returns_404(client) -> None:
    response = client.get("/api/user-employees/999", headers=_user_header())
    assert response.status_code == 404


def test_create_requires_valid_hr_employee_id(client) -> None:
    response = client.post(
        "/api/user-employees",
        json={"userId": str(uuid4()), "employeeEmail": "juan@uta.edu.ec", "hrEmployeeId": 0},
        headers=_user_header(),
    )
    assert response.status_code == 400


def test_create_update_and_delete_user_employee(client) -> None:
    user_id = uuid4()
    created = client.post(
        "/api/user-employees",
        json={"userId": str(user_id), "employeeEmail": "juan@uta.edu.ec", "hrEmployeeId": 101},
        headers=_user_header(),
    )
    assert created.status_code == 200
    entry_id = created.json()["data"]["id"]

    updated = client.put(
        f"/api/user-employees/{entry_id}", json={"notes": "Actualizado"}, headers=_user_header()
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["notes"] == "Actualizado"

    deleted = client.delete(f"/api/user-employees/{entry_id}", headers=_user_header())
    assert deleted.status_code == 200

    missing = client.get(f"/api/user-employees/{entry_id}", headers=_user_header())
    assert missing.status_code == 404
