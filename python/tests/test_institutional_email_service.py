import pytest

from repositoryuta.models.identity import ProvisioningStatus, User, UserProvisioning
from repositoryuta.services import institutional_email_service as svc
from repositoryuta.services import local_ad_service

_BASE_DN = "DC=uta,DC=edu,DC=ec"


def test_get_expected_domain_parses_base_dn() -> None:
    assert svc.get_expected_domain(_BASE_DN) == "uta.edu.ec"


def test_get_expected_domain_falls_back_when_empty() -> None:
    assert svc.get_expected_domain(None) == "uta.edu.ec"
    assert svc.get_expected_domain("") == "uta.edu.ec"


def test_generate_available_email_first_attempt(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez@uta.edu.ec"


def test_generate_available_email_single_given_name(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)

    email = svc.generate_available_email(sqlite_session, 1, "María", "Lozano", _BASE_DN)

    assert email == "m.lozano@uta.edu.ec"


def test_generate_available_email_skips_when_user_table_conflict(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)
    sqlite_session.add(
        User(id=__import__("uuid").uuid4(), email="jc.perez@uta.edu.ec", is_active=True)
    )
    sqlite_session.commit()

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez1@uta.edu.ec"


def test_generate_available_email_skips_when_provisioning_conflict_other_employee(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)
    sqlite_session.add(
        UserProvisioning(
            hr_employee_id=999,
            email="jc.perez@uta.edu.ec",
            display_name="Otro",
            employee_type_id=1,
            provisioning_status_id=int(ProvisioningStatus.CREATED_IN_LOCAL_AD),
        )
    )
    sqlite_session.commit()

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez1@uta.edu.ec"


def test_generate_available_email_ignores_provisioning_conflict_same_employee(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un registro previo del MISMO empleado no cuenta como conflicto (permite
    reintentos/actualizaciones sin bloquear el email ya asignado a el mismo)."""
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)
    sqlite_session.add(
        UserProvisioning(
            hr_employee_id=1,
            email="jc.perez@uta.edu.ec",
            display_name="Juan Carlos",
            employee_type_id=1,
            provisioning_status_id=int(ProvisioningStatus.CREATED_IN_LOCAL_AD),
        )
    )
    sqlite_session.commit()

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez@uta.edu.ec"


def test_generate_available_email_ignores_local_ad_failed_conflict(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)
    sqlite_session.add(
        UserProvisioning(
            hr_employee_id=999,
            email="jc.perez@uta.edu.ec",
            display_name="Otro",
            employee_type_id=1,
            provisioning_status_id=int(ProvisioningStatus.LOCAL_AD_FAILED),
        )
    )
    sqlite_session.commit()

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez@uta.edu.ec"


def test_generate_available_email_skips_when_ad_conflict(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Fake:
        id = "guid-1"

    monkeypatch.setattr(
        local_ad_service,
        "find_user_by_email",
        lambda email: _Fake() if email == "jc.perez@uta.edu.ec" else None,
    )

    email = svc.generate_available_email(sqlite_session, 1, "Juan Carlos", "Pérez López", _BASE_DN)

    assert email == "jc.perez1@uta.edu.ec"


def test_generate_available_email_raises_without_given_name(sqlite_session) -> None:
    with pytest.raises(ValueError, match="nombres"):
        svc.generate_available_email(sqlite_session, 1, "   ", "Pérez", _BASE_DN)


def test_generate_available_email_raises_without_surname(sqlite_session) -> None:
    with pytest.raises(ValueError, match="apellidos"):
        svc.generate_available_email(sqlite_session, 1, "Juan", "   ", _BASE_DN)


def test_generate_available_email_strips_non_ascii_and_ene(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)

    email = svc.generate_available_email(sqlite_session, 1, "Ñato", "Muñoz", _BASE_DN)

    assert email == "n.munoz@uta.edu.ec"


def test_generate_available_email_exhausts_attempts(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Fake:
        id = "guid-1"

    monkeypatch.setattr(svc, "_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: _Fake())

    with pytest.raises(ValueError, match="No se pudo generar"):
        svc.generate_available_email(sqlite_session, 1, "Juan", "Perez", _BASE_DN)
