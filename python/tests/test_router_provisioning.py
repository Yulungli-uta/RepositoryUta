from datetime import datetime
from uuid import uuid4

import pytest

from repositoryuta.core.exceptions import ConflictError
from repositoryuta.core.pagination import PagedResult
from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.schemas.provisioning import (
    BulkProvisioningResultRead,
    CompletePendingResultRead,
    DisableEmployeeResultRead,
    PasswordResetResultRead,
    UserProvisioningRead,
)
from repositoryuta.services import provisioning_service as svc


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def _sample_dto(**overrides) -> UserProvisioningRead:
    defaults = dict(
        id=str(uuid4()),
        hr_employee_id=1,
        email="jc.perez@uta.edu.ec",
        display_name="Juan Carlos Pérez",
        given_name="Juan Carlos",
        surname="Pérez",
        department_id=None,
        department_name=None,
        job_title=None,
        employee_type_id=2,
        employee_type_name="Administrativo",
        provisioning_status_id=2003,
        provisioning_status_name="PendingEntraSync",
        auth_user_id=str(uuid4()),
        local_ad_object_id="ad-guid-1",
        entra_object_id=None,
        license_sku_id=None,
        provisioned_at=datetime.now(),
        license_assigned_at=None,
        last_checked_at=datetime.now(),
        error_message=None,
        requested_by=None,
        source_reference=None,
        created_at=datetime.now(),
        updated_at=None,
    )
    defaults.update(overrides)
    return UserProvisioningRead(**defaults)


def _base_body(**overrides) -> dict:
    body = dict(
        hrEmployeeId=1,
        displayName="Juan Carlos Pérez",
        givenName="Juan Carlos",
        surname="Pérez",
        initialPassword="P@ssw0rd1",
        employeeTypeId=2,
    )
    body.update(overrides)
    return body


# ── provision ─────────────────────────────────────────────────────────────────


def test_provision_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "provision", lambda session, req: _sample_dto())

    response = client.post(
        "/api/provisioning/employees", json=_base_body(), headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "jc.perez@uta.edu.ec"


def test_provision_missing_names_returns_400(client) -> None:
    response = client.post(
        "/api/provisioning/employees",
        json=_base_body(displayName="  "),
        headers=_admin_header(),
    )
    assert response.status_code == 400


def test_provision_missing_password_returns_400(client) -> None:
    response = client.post(
        "/api/provisioning/employees",
        json=_base_body(initialPassword=""),
        headers=_admin_header(),
    )
    assert response.status_code == 400


def test_provision_invalid_hr_employee_id_returns_400(client) -> None:
    response = client.post(
        "/api/provisioning/employees",
        json=_base_body(hrEmployeeId=0),
        headers=_admin_header(),
    )
    assert response.status_code == 400


def test_provision_duplicate_returns_409(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(session, req):
        raise ConflictError("El empleado 1 ya tiene una cuenta activa")

    monkeypatch.setattr(svc, "provision", _raise)

    response = client.post(
        "/api/provisioning/employees", json=_base_body(), headers=_admin_header()
    )

    assert response.status_code == 409


def test_provision_requires_admin_role(client) -> None:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    response = client.post(
        "/api/provisioning/employees",
        json=_base_body(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


# ── bulk ──────────────────────────────────────────────────────────────────────


def test_provision_bulk_empty_returns_400(client) -> None:
    response = client.post("/api/provisioning/employees/bulk", json=[], headers=_admin_header())
    assert response.status_code == 400


def test_provision_bulk_too_many_returns_400(client) -> None:
    response = client.post(
        "/api/provisioning/employees/bulk",
        json=[_base_body(hrEmployeeId=i) for i in range(1, 202)],
        headers=_admin_header(),
    )
    assert response.status_code == 400


def test_provision_bulk_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "provision_bulk",
        lambda session, reqs: [
            BulkProvisioningResultRead(
                hr_employee_id=1,
                email="a@uta.edu.ec",
                success=True,
                provisioning=_sample_dto(),
                error=None,
            )
        ],
    )

    response = client.post(
        "/api/provisioning/employees/bulk", json=[_base_body()], headers=_admin_header()
    )

    assert response.status_code == 200
    assert "1 exitosos" in response.json()["message"]


# ── consulta ──────────────────────────────────────────────────────────────────


def test_get_status_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_status", lambda session, pid: None)

    response = client.get(f"/api/provisioning/employees/{uuid4()}", headers=_admin_header())

    assert response.status_code == 404


def test_get_status_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_status", lambda session, pid: _sample_dto())

    response = client.get(f"/api/provisioning/employees/{uuid4()}", headers=_admin_header())

    assert response.status_code == 200


def test_list_provisioning_clamps_invalid_paging(client, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def _fake(session, page, page_size, status_id):
        captured["args"] = (page, page_size, status_id)
        return PagedResult(items=[_sample_dto()], page=page, page_size=page_size, total_count=1)

    monkeypatch.setattr(svc, "list_provisioning", _fake)

    response = client.get(
        "/api/provisioning/employees?page=0&pageSize=999", headers=_admin_header()
    )

    assert response.status_code == 200
    assert captured["args"] == (1, 50, None)
    assert response.json()["data"]["totalCount"] == 1


# ── retry ─────────────────────────────────────────────────────────────────────


def test_retry_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "retry", lambda session, pid, pw: None)

    response = client.patch(
        f"/api/provisioning/employees/{uuid4()}/retry", json={}, headers=_admin_header()
    )

    assert response.status_code == 404


def test_retry_without_body(client, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def _fake(session, pid, pw):
        captured["pw"] = pw
        return _sample_dto()

    monkeypatch.setattr(svc, "retry", _fake)

    response = client.patch(f"/api/provisioning/employees/{uuid4()}/retry", headers=_admin_header())

    assert response.status_code == 200
    assert captured["pw"] is None


def test_retry_value_error_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(session, pid, pw):
        raise ValueError("Se debe proporcionar una nueva contraseña inicial")

    monkeypatch.setattr(svc, "retry", _raise)

    response = client.patch(
        f"/api/provisioning/employees/{uuid4()}/retry", json={}, headers=_admin_header()
    )

    assert response.status_code == 400


# ── complete ──────────────────────────────────────────────────────────────────


def test_complete_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "check_and_complete_provisioning", lambda session, pid: None)

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/complete", headers=_admin_header()
    )

    assert response.status_code == 404


def test_complete_pending(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "complete_pending",
        lambda session: CompletePendingResultRead(
            total_processed=2, license_assigned=1, still_pending=1, failed=0, results=[]
        ),
    )

    response = client.post("/api/provisioning/employees/complete-pending", headers=_admin_header())

    assert response.status_code == 200
    assert "Procesados: 2" in response.json()["message"]


# ── reset-password ───────────────────────────────────────────────────────────


def test_reset_password_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "reset_password", lambda session, pid: None)

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/reset-password", headers=_admin_header()
    )

    assert response.status_code == 404


def test_reset_password_no_ad_account_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(session, pid):
        raise ValueError("El empleado no tiene cuenta en AD Local")

    monkeypatch.setattr(svc, "reset_password", _raise)

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/reset-password", headers=_admin_header()
    )

    assert response.status_code == 400


def test_reset_password_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "reset_password",
        lambda session, pid: PasswordResetResultRead(
            provisioning_id=str(uuid4()),
            hr_employee_id=1,
            email="a@uta.edu.ec",
            new_temporary_password="Temp123!abc",
            message="ok",
        ),
    )

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/reset-password", headers=_admin_header()
    )

    assert response.status_code == 200


# ── disable ───────────────────────────────────────────────────────────────────


def test_disable_by_hr_employee_id(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_employee",
        lambda session, hr_id: DisableEmployeeResultRead(
            success=True, hr_employee_id=hr_id, email="a@uta.edu.ec", error_message=None
        ),
    )

    response = client.post("/api/provisioning/employees/5/disable", headers=_admin_header())

    assert response.status_code == 200


def test_disable_by_provisioning_guid(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_by_provisioning_id",
        lambda session, pid: DisableEmployeeResultRead(
            success=True, hr_employee_id=1, email="a@uta.edu.ec", error_message=None
        ),
    )

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/disable", headers=_admin_header()
    )

    assert response.status_code == 200


def test_disable_by_provisioning_guid_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "disable_by_provisioning_id", lambda session, pid: None)

    response = client.post(
        f"/api/provisioning/employees/{uuid4()}/disable", headers=_admin_header()
    )

    assert response.status_code == 404


def test_disable_invalid_identifier_returns_404(client) -> None:
    response = client.post(
        "/api/provisioning/employees/not-a-valid-id/disable", headers=_admin_header()
    )
    assert response.status_code == 404


def test_disable_failure_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_employee",
        lambda session, hr_id: DisableEmployeeResultRead(
            success=False, hr_employee_id=hr_id, email=None, error_message="No se encontró cuenta"
        ),
    )

    response = client.post("/api/provisioning/employees/5/disable", headers=_admin_header())

    assert response.status_code == 400


def test_disable_by_ad_object_id(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_by_ad_id",
        lambda session, ad_id: DisableEmployeeResultRead(
            success=True, hr_employee_id=1, email="a@uta.edu.ec", error_message=None
        ),
    )

    response = client.post(
        "/api/provisioning/employees/by-ad-id/guid-1/disable", headers=_admin_header()
    )

    assert response.status_code == 200


def test_disable_by_ad_object_id_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "disable_by_ad_id", lambda session, ad_id: None)

    response = client.post(
        "/api/provisioning/employees/by-ad-id/guid-1/disable", headers=_admin_header()
    )

    assert response.status_code == 404
