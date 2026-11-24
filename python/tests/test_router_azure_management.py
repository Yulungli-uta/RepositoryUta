from uuid import uuid4

import pytest

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.schemas.azure_management import (
    AzureGroupRead,
    AzureUserRead,
    BulkOperationResultRead,
)
from repositoryuta.services import azure_management_service as svc


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def _sample_user(**overrides) -> AzureUserRead:
    defaults = dict(
        id=str(uuid4()),
        email="juan@uta.edu.ec",
        display_name="Juan Perez",
        given_name=None,
        surname=None,
        job_title=None,
        department=None,
        office_location=None,
        mobile_phone=None,
        business_phones=None,
        street_address=None,
        city=None,
        state=None,
        country=None,
        postal_code=None,
        usage_location=None,
        employee_id=None,
        company_name=None,
        account_enabled=True,
        created_date_time=None,
        last_password_change_date_time=None,
        user_type=None,
        assigned_licenses=None,
    )
    defaults.update(overrides)
    return AzureUserRead(**defaults)


def _sample_group(**overrides) -> AzureGroupRead:
    defaults = dict(
        id=str(uuid4()),
        display_name="Docentes",
        description=None,
        mail=None,
        mail_nickname=None,
        mail_enabled=False,
        security_enabled=True,
        group_type="Security",
        created_date_time=None,
        member_count=0,
        group_types=None,
    )
    defaults.update(overrides)
    return AzureGroupRead(**defaults)


def test_create_user_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "create_user_in_azure", lambda session, dto: _sample_user())

    response = client.post(
        "/api/azure-management/users",
        json={
            "email": "juan@uta.edu.ec",
            "displayName": "Juan Perez",
            "givenName": "Juan",
            "surname": "Perez",
            "password": "Sup3r$ecurePass!",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "juan@uta.edu.ec"


def test_create_user_error_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(session, dto):
        raise ValueError("Email inválido")

    monkeypatch.setattr(svc, "create_user_in_azure", _raise)

    response = client.post(
        "/api/azure-management/users",
        json={
            "email": "bad",
            "displayName": "Juan Perez",
            "givenName": "Juan",
            "surname": "Perez",
            "password": "Sup3r$ecurePass!",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 400


def test_get_user_not_found_returns_404(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_user_from_azure", lambda azure_object_id: None)

    response = client.get(f"/api/azure-management/users/{uuid4()}", headers=_admin_header())

    assert response.status_code == 404


def test_get_user_by_email(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc, "get_user_by_email_from_azure", lambda email: _sample_user(email=email)
    )

    response = client.get(
        "/api/azure-management/users/by-email/juan@uta.edu.ec", headers=_admin_header()
    )

    assert response.status_code == 200


def test_enable_user(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "enable_disable_user_in_azure", lambda session, oid, enable: True)

    response = client.post(
        f"/api/azure-management/users/{uuid4()}/enable", headers=_admin_header()
    )

    assert response.status_code == 200


def test_delete_user_failure_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "delete_user_from_azure", lambda session, oid, permanent: False)

    response = client.delete(f"/api/azure-management/users/{uuid4()}", headers=_admin_header())

    assert response.status_code == 400


def test_list_users(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "list_users_from_azure",
        lambda page, page_size, filter: svc.PagedAzureResult(
            items=[_sample_user()], page=page, page_size=page_size, total_count=1
        ),
    )

    response = client.get("/api/azure-management/users", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["totalCount"] == 1


def test_reset_password(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc, "reset_password_in_azure", lambda session, oid, force_change: "TempPass123!"
    )

    response = client.post(
        f"/api/azure-management/users/{uuid4()}/reset-password", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["temporaryPassword"] == "TempPass123!"


def test_change_password(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc, "change_password_in_azure", lambda session, oid, pw, force: True
    )

    response = client.post(
        f"/api/azure-management/users/{uuid4()}/change-password",
        json={"newPassword": "NewP@ss1", "forceChangeNextSignIn": True},
        headers=_admin_header(),
    )

    assert response.status_code == 200


def test_validate_password(client) -> None:
    response = client.post(
        "/api/azure-management/validate-password", json="weak", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["isValid"] is False


def test_generate_password(client) -> None:
    response = client.get("/api/azure-management/generate-password", headers=_admin_header())

    assert response.status_code == 200
    assert len(response.json()["data"]["password"]) == 16


def test_get_all_azure_roles(client, monkeypatch: pytest.MonkeyPatch) -> None:
    from repositoryuta.schemas.azure_management import AzureRoleRead

    monkeypatch.setattr(
        svc,
        "get_all_azure_directory_roles",
        lambda: [
            AzureRoleRead(
                id="r1", display_name="Global Admin", description=None, is_built_in=True,
                role_template_id=None,
            )
        ],
    )

    response = client.get("/api/azure-management/azure-roles", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"][0]["displayName"] == "Global Admin"


def test_assign_azure_role_failure_returns_400(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "assign_azure_role", lambda session, user_id, role_id: False)

    response = client.post(
        f"/api/azure-management/users/{uuid4()}/azure-roles/role-id", headers=_admin_header()
    )

    assert response.status_code == 400


def test_create_group_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "create_group_in_azure", lambda session, dto: _sample_group())

    response = client.post(
        "/api/azure-management/groups", json={"displayName": "Docentes"}, headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["displayName"] == "Docentes"


def test_get_group_not_found(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_group_from_azure", lambda group_id: None)

    response = client.get(f"/api/azure-management/groups/{uuid4()}", headers=_admin_header())

    assert response.status_code == 404


def test_list_groups(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "list_groups_from_azure",
        lambda page, page_size, filter: svc.PagedAzureResult(
            items=[_sample_group()], page=page, page_size=page_size, total_count=1
        ),
    )

    response = client.get("/api/azure-management/groups", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["totalCount"] == 1


def test_add_user_to_group(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "add_user_to_azure_group", lambda session, g, u: True)

    response = client.post(
        f"/api/azure-management/groups/group-id/members/{uuid4()}", headers=_admin_header()
    )

    assert response.status_code == 200


def test_bulk_create_users(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "bulk_create_users",
        lambda session, users: BulkOperationResultRead(
            total_requested=1, successful=1, failed=0, errors=[], duration_seconds=0.1
        ),
    )

    response = client.post(
        "/api/azure-management/users/bulk-create",
        json=[
            {
                "email": "juan@uta.edu.ec",
                "displayName": "Juan Perez",
                "givenName": "Juan",
                "surname": "Perez",
                "password": "Sup3r$ecurePass!",
            }
        ],
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["successful"] == 1


def test_bulk_add_users_to_group(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "bulk_add_users_to_group",
        lambda session, group_id, user_ids: BulkOperationResultRead(
            total_requested=len(user_ids), successful=len(user_ids), failed=0, errors=[],
            duration_seconds=0.1,
        ),
    )

    response = client.post(
        "/api/azure-management/groups/group-id/members/bulk-add",
        json=["u1", "u2"],
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["totalRequested"] == 2


def test_sync_user_to_local_db(client, monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import datetime

    from repositoryuta.schemas.azure_management import SyncResultRead

    monkeypatch.setattr(
        svc,
        "sync_user_to_local_db",
        lambda session, oid: SyncResultRead(
            success=True, users_processed=1, users_created=1, users_updated=0, users_failed=0,
            groups_processed=0, groups_created=0, groups_updated=0, errors=[],
            sync_date_time=datetime.now(), duration_seconds=0.1,
        ),
    )

    response = client.post(
        f"/api/azure-management/sync/user/{uuid4()}", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["success"] is True


def test_endpoints_require_admin_role(client) -> None:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/azure-management/users", headers=headers)

    assert response.status_code == 403
