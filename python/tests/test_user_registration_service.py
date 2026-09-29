from uuid import uuid4

import pytest

from repositoryuta.core.exceptions import ConflictError
from repositoryuta.models.identity import User, UserEmployee
from repositoryuta.schemas.identity import UserCreate
from repositoryuta.services.user_registration_service import create_user_with_employee


def test_creates_user_and_employee_together(sqlite_session) -> None:
    dto = UserCreate(email="juan.perez@uta.edu.ec", display_name="Juan Perez", hr_employee_id=42)

    user, user_employee = create_user_with_employee(sqlite_session, dto)

    assert user.email == "juan.perez@uta.edu.ec"
    assert user.user_type == "Local"
    assert user_employee.user_id == user.id
    assert user_employee.hr_employee_id == 42


def test_hr_employee_id_zero_becomes_none_not_a_false_zero(sqlite_session) -> None:
    dto = UserCreate(email="cuenta.servicio@uta.edu.ec", hr_employee_id=0)

    _, user_employee = create_user_with_employee(sqlite_session, dto)

    assert user_employee.hr_employee_id is None


def test_rejects_duplicate_email_in_users(sqlite_session) -> None:
    sqlite_session.add(User(id=uuid4(), email="juan@uta.edu.ec"))
    sqlite_session.flush()

    with pytest.raises(ConflictError, match="Ya existe un usuario"):
        create_user_with_employee(
            sqlite_session, UserCreate(email="juan@uta.edu.ec", hr_employee_id=1)
        )


def test_rejects_duplicate_email_in_user_employees(sqlite_session) -> None:
    sqlite_session.add(
        UserEmployee(user_id=uuid4(), employee_email="ana@uta.edu.ec", hr_employee_id=5)
    )
    sqlite_session.flush()

    with pytest.raises(ConflictError, match="Ya existe un UserEmployee"):
        create_user_with_employee(
            sqlite_session, UserCreate(email="ana@uta.edu.ec", hr_employee_id=1)
        )
