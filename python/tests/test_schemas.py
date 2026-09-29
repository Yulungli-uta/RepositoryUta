from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from repositoryuta.schemas.app_param import AppParamCreate
from repositoryuta.schemas.auth import LoginRequest, TokenPair, ValidateTokenRequest
from repositoryuta.schemas.common import ApiResponse
from repositoryuta.schemas.identity import UserCreate
from repositoryuta.schemas.rbac import UserRoleCreate
from repositoryuta.schemas.session import UserSessionCreate


def test_user_create_requires_hr_employee_id() -> None:
    with pytest.raises(ValidationError):
        UserCreate(email="juan@uta.edu.ec", display_name="Juan")


def test_user_create_defaults_user_type_to_local() -> None:
    dto = UserCreate(email="juan@uta.edu.ec", display_name="Juan", hr_employee_id=42)

    assert dto.user_type == "Local"


def test_user_role_create_rejects_non_uuid_user_id() -> None:
    with pytest.raises(ValidationError):
        UserRoleCreate(user_id="not-a-uuid", role_id=1)


def test_app_param_create_requires_nemonic_and_value() -> None:
    with pytest.raises(ValidationError):
        AppParamCreate(value="45")

    dto = AppParamCreate(nemonic="Jwt:AccessTokenLifetimeMinutes", value="45")
    assert dto.nemonic == "Jwt:AccessTokenLifetimeMinutes"


def test_login_request_requires_email_and_password() -> None:
    with pytest.raises(ValidationError):
        LoginRequest(email="juan@uta.edu.ec")

    assert LoginRequest(email="juan@uta.edu.ec", password="x").password == "x"


def test_validate_token_request_and_token_pair_shapes() -> None:
    request = ValidateTokenRequest(token="jwt-value")
    assert request.client_id is None

    pair = TokenPair(access_token="a", refresh_token="b")
    assert pair.access_token == "a"


def test_user_session_create_requires_expires_at() -> None:
    with pytest.raises(ValidationError):
        UserSessionCreate(
            user_id="6b8fe56d-1006-4fb8-b6f8-9c6592ecbde4",
            access_token="a",
            refresh_token="b",
        )

    dto = UserSessionCreate(
        user_id="6b8fe56d-1006-4fb8-b6f8-9c6592ecbde4",
        access_token="a",
        refresh_token="b",
        expires_at=datetime.now() + timedelta(hours=1),
    )
    assert dto.access_token == "a"


def test_api_response_ok_and_fail_factories() -> None:
    ok = ApiResponse.ok(data={"id": 1}, message="Creado")
    assert ok.success is True
    assert ok.errors is None

    fail = ApiResponse.fail("No existe", errors=["Usuario no encontrado"])
    assert fail.success is False
    assert fail.data is None
    assert fail.errors == ["Usuario no encontrado"]
