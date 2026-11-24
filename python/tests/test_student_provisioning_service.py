import pytest

from repositoryuta.config import get_settings
from repositoryuta.schemas.provisioning import CreateStudentAdAccountRequest
from repositoryuta.services import institutional_email_service, local_ad_service
from repositoryuta.services import student_provisioning_service as svc
from repositoryuta.services.local_ad_service import DirectoryGroup, DirectoryUser


@pytest.fixture(autouse=True)
def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings().local_ad, "base_dn", "DC=uta,DC=edu,DC=ec")
    monkeypatch.setattr(
        get_settings().local_ad,
        "estudiantes_activos_ou",
        "OU=Activos,OU=ESTUDIANTES,DC=uta,DC=edu,DC=ec",
    )
    monkeypatch.setattr(
        get_settings().local_ad,
        "estudiantes_inactivos_ou",
        "OU=Inactivos,OU=ESTUDIANTES,DC=uta,DC=edu,DC=ec",
    )
    monkeypatch.setattr(get_settings().provisioning, "grupo_estudiantes_activos_cn", "EActivos")
    monkeypatch.setattr(
        institutional_email_service,
        "generate_available_email",
        lambda session, hr_id, given_name, surname, base_dn: "jp.smith@uta.edu.ec",
    )


def _req(**overrides) -> CreateStudentAdAccountRequest:
    defaults = dict(
        hr_student_id=10,
        display_name="Juan Pérez Smith",
        given_name="Juan",
        surname="Pérez Smith",
        initial_password="P@ssw0rd1",
    )
    defaults.update(overrides)
    return CreateStudentAdAccountRequest(**defaults)


def test_create_ad_account_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "create_user",
        lambda user, pw, ou, force: DirectoryUser(
            id="ad-guid-1",
            email=user.email,
            display_name=user.display_name,
            given_name=user.given_name,
            surname=user.surname,
            job_title=None,
            department=None,
            is_enabled=True,
        ),
    )
    monkeypatch.setattr(
        local_ad_service,
        "list_groups",
        lambda **kw: [DirectoryGroup(id="group-1", name="EActivos", description=None, email=None)],
    )
    added = {}
    monkeypatch.setattr(
        local_ad_service,
        "add_user_to_group",
        lambda g, u: added.update(group=g, user=u),
    )

    result = svc.create_ad_account(sqlite_session, _req())

    assert result.success is True
    assert result.ad_object_id == "ad-guid-1"
    assert result.email == "jp.smith@uta.edu.ec"
    assert added == {"group": "group-1", "user": "ad-guid-1"}


def test_create_ad_account_email_generation_failure(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*a, **k):
        raise ValueError("sin nombres")

    monkeypatch.setattr(institutional_email_service, "generate_available_email", _raise)

    result = svc.create_ad_account(sqlite_session, _req())

    assert result.success is False
    assert result.email is None
    assert "sin nombres" in result.error_message


def test_create_ad_account_ad_creation_failure_keeps_generated_email(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise(*a, **k):
        raise RuntimeError("LDAP no disponible")

    monkeypatch.setattr(local_ad_service, "create_user", _raise)

    result = svc.create_ad_account(sqlite_session, _req())

    assert result.success is False
    assert result.ad_object_id is None
    assert result.email == "jp.smith@uta.edu.ec"
    assert "LDAP no disponible" in result.error_message


def test_create_ad_account_group_not_found_does_not_fail(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "create_user",
        lambda user, pw, ou, force: DirectoryUser(
            id="ad-guid-1",
            email=user.email,
            display_name=user.display_name,
            given_name=user.given_name,
            surname=user.surname,
            job_title=None,
            department=None,
            is_enabled=True,
        ),
    )
    monkeypatch.setattr(local_ad_service, "list_groups", lambda **kw: [])

    result = svc.create_ad_account(sqlite_session, _req())

    assert result.success is True


def test_create_ad_account_group_add_failure_does_not_fail(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "create_user",
        lambda user, pw, ou, force: DirectoryUser(
            id="ad-guid-1",
            email=user.email,
            display_name=user.display_name,
            given_name=user.given_name,
            surname=user.surname,
            job_title=None,
            department=None,
            is_enabled=True,
        ),
    )
    monkeypatch.setattr(
        local_ad_service,
        "list_groups",
        lambda **kw: [DirectoryGroup(id="group-1", name="EActivos", description=None, email=None)],
    )

    def _raise(*a, **k):
        raise RuntimeError("no se pudo agregar")

    monkeypatch.setattr(local_ad_service, "add_user_to_group", _raise)

    result = svc.create_ad_account(sqlite_session, _req())

    assert result.success is True


def test_disable_ad_account_success(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        local_ad_service, "set_user_enabled", lambda i, e: calls.append(("enable", i, e))
    )
    monkeypatch.setattr(
        local_ad_service, "move_user_to_ou", lambda i, ou: calls.append(("move", i, ou))
    )
    monkeypatch.setattr(
        local_ad_service, "remove_user_from_group", lambda g, i: calls.append(("remove", g, i))
    )

    result = svc.disable_ad_account("ad-guid-1")

    assert result.success is True
    assert ("enable", "ad-guid-1", False) in calls
    assert ("move", "ad-guid-1", "OU=Inactivos,OU=ESTUDIANTES,DC=uta,DC=edu,DC=ec") in calls
    assert ("remove", "EActivos", "ad-guid-1") in calls


def test_disable_ad_account_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a, **k):
        raise RuntimeError("AD caído")

    monkeypatch.setattr(local_ad_service, "set_user_enabled", _raise)

    result = svc.disable_ad_account("ad-guid-1")

    assert result.success is False
    assert result.ad_object_id == "ad-guid-1"
    assert "AD caído" in result.error_message


def test_disable_ad_account_move_failure_does_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "set_user_enabled", lambda i, e: None)

    def _raise(*a, **k):
        raise RuntimeError("no se pudo mover")

    monkeypatch.setattr(local_ad_service, "move_user_to_ou", _raise)
    monkeypatch.setattr(local_ad_service, "remove_user_from_group", lambda g, i: None)

    result = svc.disable_ad_account("ad-guid-1")

    assert result.success is True
