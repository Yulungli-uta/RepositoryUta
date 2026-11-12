from uuid import uuid4

import pytest

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.schemas.provisioning import (
    CreateStudentAdAccountResultRead,
    DisableStudentAdAccountResultRead,
)
from repositoryuta.services import student_provisioning_service as svc


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_create_ad_account_success_response_shape(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "create_ad_account",
        lambda session, req: CreateStudentAdAccountResultRead(
            success=True, ad_object_id="ad-1", email="jp@uta.edu.ec", error_message=None
        ),
    )

    response = client.post(
        "/api/academic/student-provisioning/students",
        json={
            "hrStudentId": 10,
            "displayName": "Juan Pérez",
            "givenName": "Juan",
            "surname": "Pérez",
            "initialPassword": "P@ssw0rd1",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 200
    body = response.json()
    assert "error" not in body
    assert body["data"]["adObjectId"] == "ad-1"


def test_create_ad_account_failure_response_shape(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "create_ad_account",
        lambda session, req: CreateStudentAdAccountResultRead(
            success=False, ad_object_id=None, email=None, error_message="LDAP no disponible"
        ),
    )

    response = client.post(
        "/api/academic/student-provisioning/students",
        json={
            "hrStudentId": 10,
            "displayName": "Juan Pérez",
            "givenName": "Juan",
            "surname": "Pérez",
            "initialPassword": "P@ssw0rd1",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "LDAP no disponible"
    assert body["data"]["success"] is False


def test_disable_ad_account_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_ad_account",
        lambda ad_id: DisableStudentAdAccountResultRead(
            success=True, ad_object_id=ad_id, error_message=None
        ),
    )

    response = client.post(
        "/api/academic/student-provisioning/ad-accounts/ad-1/disable", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["adObjectId"] == "ad-1"


def test_disable_ad_account_failure(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "disable_ad_account",
        lambda ad_id: DisableStudentAdAccountResultRead(
            success=False, ad_object_id=ad_id, error_message="AD caído"
        ),
    )

    response = client.post(
        "/api/academic/student-provisioning/ad-accounts/ad-1/disable", headers=_admin_header()
    )

    assert response.status_code == 400
    assert response.json()["error"] == "AD caído"


def test_requires_admin_role(client) -> None:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    response = client.post(
        "/api/academic/student-provisioning/ad-accounts/ad-1/disable",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_ditic_role_alone_is_not_enough(client) -> None:
    """A diferencia de ProvisioningController, este controller solo acepta
    'Administrador' — R_DITIC NO basta (Authorize(Roles = "Administrador") sin
    R_DITIC en el .NET original)."""
    token = create_user_token(str(uuid4()), "ditic@uta.edu.ec", ["R_DITIC"])
    response = client.post(
        "/api/academic/student-provisioning/ad-accounts/ad-1/disable",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
