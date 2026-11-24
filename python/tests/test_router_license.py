from uuid import uuid4

import pytest

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.schemas.license import LicenseOperationResultRead, SubscribedSkuRead
from repositoryuta.services import license_service as svc


def _auth_header(roles: list[str] | None = None) -> dict[str, str]:
    token = create_user_token(str(uuid4()), "empleado@uta.edu.ec", roles or ["R_EMPLOYEE"])
    return {"Authorization": f"Bearer {token}"}


def _sample_sku(**overrides) -> SubscribedSkuRead:
    defaults = dict(
        sku_id=str(uuid4()),
        sku_part_number="STANDARDWOFFPACK_FACULTY",
        capability_status="Enabled",
        prepaid_units_enabled=100,
        consumed_units=40,
        available_units=60,
    )
    defaults.update(overrides)
    return SubscribedSkuRead(**defaults)


def test_get_skus_does_not_require_admin_role(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_subscribed_skus", lambda: [_sample_sku()])

    response = client.get("/api/licenses/skus", headers=_auth_header())

    assert response.status_code == 200
    assert response.json()["data"][0]["skuPartNumber"] == "STANDARDWOFFPACK_FACULTY"


def test_get_skus_requires_authentication(client) -> None:
    response = client.get("/api/licenses/skus")

    assert response.status_code == 401


def test_get_user_licenses(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "get_user_licenses", lambda upn: [])

    response = client.get("/api/licenses/users/juan@uta.edu.ec", headers=_auth_header())

    assert response.status_code == 200
    assert response.json()["message"] == "0 licencia(s) asignadas a juan@uta.edu.ec"


def test_assign_missing_fields_returns_400(client) -> None:
    response = client.post(
        "/api/licenses/assign",
        json={"upn": "  ", "skuPartNumber": "X"},
        headers=_auth_header(),
    )

    assert response.status_code == 400


def test_assign_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "assign_license",
        lambda upn, sku, country="EC": LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number=sku, sku_id="x", message="ok"
        ),
    )

    response = client.post(
        "/api/licenses/assign",
        json={"upn": "juan@uta.edu.ec", "skuPartNumber": "STANDARDWOFFPACK_FACULTY"},
        headers=_auth_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["success"] is True


def test_assign_failure_returns_422(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "assign_license",
        lambda upn, sku, country="EC": LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number=sku, sku_id=None, message="sin cupos"
        ),
    )

    response = client.post(
        "/api/licenses/assign",
        json={"upn": "juan@uta.edu.ec", "skuPartNumber": "STANDARDWOFFPACK_FACULTY"},
        headers=_auth_header(),
    )

    assert response.status_code == 422


def test_assign_employee_missing_upn_returns_400(client) -> None:
    response = client.post(
        "/api/licenses/assign-employee", json={"upn": ""}, headers=_auth_header()
    )

    assert response.status_code == 400


def test_assign_employee_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "assign_employee_license",
        lambda session, upn, country="EC": LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number="STD", sku_id="x", message="ok"
        ),
    )

    response = client.post(
        "/api/licenses/assign-employee", json={"upn": "juan@uta.edu.ec"}, headers=_auth_header()
    )

    assert response.status_code == 200


def test_remove_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "remove_license",
        lambda upn, sku: LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number=sku, sku_id="x", message="ok"
        ),
    )

    response = client.post(
        "/api/licenses/remove",
        json={"upn": "juan@uta.edu.ec", "skuPartNumber": "STANDARDWOFFPACK_FACULTY"},
        headers=_auth_header(),
    )

    assert response.status_code == 200


def test_remove_failure_returns_422(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "remove_license",
        lambda upn, sku: LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number=sku, sku_id=None, message="no encontrado"
        ),
    )

    response = client.post(
        "/api/licenses/remove",
        json={"upn": "juan@uta.edu.ec", "skuPartNumber": "STANDARDWOFFPACK_FACULTY"},
        headers=_auth_header(),
    )

    assert response.status_code == 422


def test_set_usage_location(client, monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def _fake(upn, country_code):
        captured["args"] = (upn, country_code)

    monkeypatch.setattr(svc, "set_usage_location", _fake)

    response = client.patch(
        "/api/licenses/users/juan@uta.edu.ec/usage-location?countryCode=PE",
        headers=_auth_header(),
    )

    assert response.status_code == 200
    assert captured["args"] == ("juan@uta.edu.ec", "PE")
