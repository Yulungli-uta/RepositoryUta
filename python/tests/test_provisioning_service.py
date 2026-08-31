from uuid import UUID, uuid4

import pytest

from repositoryuta.config import get_settings
from repositoryuta.models.identity import ProvisioningStatus, User, UserEmployee, UserProvisioning
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.schemas.license import LicenseOperationResultRead
from repositoryuta.schemas.provisioning import ProvisionEmployeeRequest
from repositoryuta.services import azure_management_service as azure_mgmt
from repositoryuta.services import institutional_email_service, license_service, local_ad_service
from repositoryuta.services import provisioning_service as svc
from repositoryuta.services.azure_management_service import EntraSyncResult, EntraSyncStatus
from repositoryuta.services.local_ad_service import DirectoryUser


@pytest.fixture(autouse=True)
def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings().local_ad, "base_dn", "DC=uta,DC=edu,DC=ec")
    monkeypatch.setattr(
        get_settings().local_ad, "funcionarios_activos_ou", "OU=Activos,DC=uta,DC=edu,DC=ec"
    )
    monkeypatch.setattr(
        get_settings().local_ad, "funcionarios_inactivos_ou", "OU=Inactivos,DC=uta,DC=edu,DC=ec"
    )
    monkeypatch.setattr(
        get_settings().local_ad, "estudiantes_inactivos_ou", "OU=EInactivos,DC=uta,DC=edu,DC=ec"
    )
    monkeypatch.setattr(get_settings().provisioning, "default_role_names", ["Empleado"])
    monkeypatch.setattr(get_settings().provisioning, "grupo_funcionarios_activos_cn", "UActivos")
    monkeypatch.setattr(get_settings().provisioning, "grupo_estudiantes_activos_cn", "EActivos")
    monkeypatch.setattr(get_settings().provisioning, "student_employee_type_ids", [])
    monkeypatch.setattr(
        institutional_email_service,
        "generate_available_email",
        lambda session, hr_employee_id, given_name, surname, base_dn: "jc.perez@uta.edu.ec",
    )


def _req(**overrides) -> ProvisionEmployeeRequest:
    defaults = dict(
        hr_employee_id=1,
        display_name="Juan Carlos Pérez",
        given_name="Juan Carlos",
        surname="Pérez",
        initial_password="P@ssw0rd1",
        employee_type_id=2,
        employee_type_name="Administrativo",
    )
    defaults.update(overrides)
    return ProvisionEmployeeRequest(**defaults)


def _ad_user(**overrides) -> DirectoryUser:
    defaults = dict(
        id=str(uuid4()),
        email="jc.perez@uta.edu.ec",
        display_name="Juan Carlos Pérez",
        given_name="Juan Carlos",
        surname="Pérez",
        job_title=None,
        department=None,
        is_enabled=True,
    )
    defaults.update(overrides)
    return DirectoryUser(**defaults)


def _stub_success_chain(
    monkeypatch: pytest.MonkeyPatch, sync_status=EntraSyncStatus.PENDING_SYNC
) -> None:
    monkeypatch.setattr(local_ad_service, "create_user", lambda *a, **k: _ad_user())
    monkeypatch.setattr(local_ad_service, "is_user_in_group", lambda g, u: False)
    monkeypatch.setattr(local_ad_service, "add_user_to_group", lambda g, u: None)
    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=sync_status, message="pendiente"),
    )


# ── provision ─────────────────────────────────────────────────────────────────


def test_provision_success_pending_entra_sync(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_success_chain(monkeypatch)

    result = svc.provision(sqlite_session, _req())

    assert result.email == "jc.perez@uta.edu.ec"
    assert result.provisioning_status_name == "PendingEntraSync"
    assert result.local_ad_object_id is not None
    assert result.auth_user_id is not None
    assert sqlite_session.query(User).filter_by(email="jc.perez@uta.edu.ec").count() == 1
    assert sqlite_session.query(UserEmployee).filter_by(hr_employee_id=1).count() == 1


def test_provision_assigns_default_role(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_success_chain(monkeypatch)
    sqlite_session.add(Role(name="Empleado", is_active=True))
    sqlite_session.commit()

    result = svc.provision(sqlite_session, _req())

    user_id = UUID(result.auth_user_id)
    assert sqlite_session.query(UserRole).filter_by(user_id=user_id).count() == 1


def test_provision_missing_role_does_not_fail(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Un rol configurado que no existe en auth.tbl_Roles se loguea y se omite,
    sin abortar el aprovisionamiento (fidelidad con EnsureDefaultRoleAsync)."""
    _stub_success_chain(monkeypatch)

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "PendingEntraSync"


def test_provision_synced_entra_sets_object_id(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_success_chain(monkeypatch)
    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.SYNCED, azure_object_id="azure-1"),
    )

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "SyncedInEntra"
    assert result.entra_object_id == "azure-1"


def test_provision_duplicate_raises_conflict(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_success_chain(monkeypatch)
    from repositoryuta.core.exceptions import ConflictError

    svc.provision(sqlite_session, _req())

    with pytest.raises(ConflictError):
        svc.provision(sqlite_session, _req(hr_employee_id=1))


def test_provision_allows_retry_after_local_ad_failed(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_ad(*a, **k):
        raise RuntimeError("LDAP down")

    monkeypatch.setattr(local_ad_service, "create_user", _raise_ad)

    result = svc.provision(sqlite_session, _req())
    assert result.provisioning_status_name == "LocalAdFailed"

    _stub_success_chain(monkeypatch)
    result2 = svc.provision(sqlite_session, _req(hr_employee_id=1))
    assert result2.provisioning_status_name == "PendingEntraSync"


def test_provision_ad_creation_failure_marks_local_ad_failed(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_ad(*a, **k):
        raise RuntimeError("LDAP no disponible")

    monkeypatch.setattr(local_ad_service, "create_user", _raise_ad)

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "LocalAdFailed"
    assert "LDAP no disponible" in result.error_message
    assert result.local_ad_object_id is None
    # el registro inicial ya se persistio (checkpoint A) aun con el fallo posterior
    assert sqlite_session.query(UserProvisioning).filter_by(hr_employee_id=1).count() == 1


def test_provision_missing_target_ou_marks_local_ad_failed(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings().local_ad, "funcionarios_activos_ou", None)

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "LocalAdFailed"
    assert "FuncionariosActivosOu" in result.error_message


def test_provision_wrong_domain_marks_local_ad_failed(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        institutional_email_service,
        "generate_available_email",
        lambda *a, **k: "jc.perez@gmail.com",
    )

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "LocalAdFailed"
    assert "dominio institucional" in result.error_message


def test_provision_cn_warning_is_overwritten_by_entra_sync_status(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fidelidad con un comportamiento real (y probablemente no intencional)
    del .NET: UpdateStatusAsync sobreescribe ErrorMessage sin condicion en
    cada transicion de estado, asi que el aviso [AVISO] del ajuste de CN queda
    pisado por el mensaje del chequeo de Entra sync que ocurre justo despues,
    en la MISMA request — un caller real nunca llega a ver este warning por la
    API. Se replica tal cual, no se "arregla" sin aprobacion explicita."""
    _stub_success_chain(monkeypatch)
    monkeypatch.setattr(
        local_ad_service,
        "create_user",
        lambda *a, **k: _ad_user(cn_warning="CN ya existía, se usó 'Juan Carlos Pérez 1'"),
    )

    result = svc.provision(sqlite_session, _req())

    assert result.warning is None
    assert result.error_message == "pendiente"


def test_provision_entra_sync_exception_marks_pending(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(local_ad_service, "create_user", lambda *a, **k: _ad_user())
    monkeypatch.setattr(local_ad_service, "is_user_in_group", lambda g, u: False)
    monkeypatch.setattr(local_ad_service, "add_user_to_group", lambda g, u: None)

    def _raise_sync(upn):
        raise RuntimeError("Graph caído")

    monkeypatch.setattr(azure_mgmt, "check_user_entra_sync", _raise_sync)

    result = svc.provision(sqlite_session, _req())

    assert result.provisioning_status_name == "PendingEntraSync"


# ── provision_bulk ────────────────────────────────────────────────────────────


def test_provision_bulk_mixed_results(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_success_chain(monkeypatch)

    results = svc.provision_bulk(sqlite_session, [_req(hr_employee_id=1), _req(hr_employee_id=1)])

    assert results[0].success is True
    assert results[1].success is False
    assert "cuenta activa" in results[1].error


# ── get_status / list ─────────────────────────────────────────────────────────


def test_get_status_not_found(sqlite_session) -> None:
    assert svc.get_status(sqlite_session, uuid4()) is None


def test_list_provisioning_filters_by_status(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_success_chain(monkeypatch)
    monkeypatch.setattr(
        institutional_email_service,
        "generate_available_email",
        lambda session, hr_employee_id, given_name, surname, base_dn: (
            f"emp{hr_employee_id}@uta.edu.ec"
        ),
    )
    svc.provision(sqlite_session, _req(hr_employee_id=1))
    svc.provision(sqlite_session, _req(hr_employee_id=2))

    result = svc.list_provisioning(
        sqlite_session, 1, 50, status_id=int(ProvisioningStatus.PENDING_ENTRA_SYNC)
    )

    assert result.total_count == 2
    assert len(result.items) == 2


# ── retry ─────────────────────────────────────────────────────────────────────


def test_retry_not_found(sqlite_session) -> None:
    assert svc.retry(sqlite_session, uuid4(), "P@ssw0rd1") is None


def test_retry_local_ad_failed_requires_password(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_ad(*a, **k):
        raise RuntimeError("LDAP down")

    monkeypatch.setattr(local_ad_service, "create_user", _raise_ad)
    result = svc.provision(sqlite_session, _req())
    assert result.provisioning_status_name == "LocalAdFailed"

    with pytest.raises(ValueError, match="contraseña inicial"):
        svc.retry(sqlite_session, UUID(result.id), None)


def test_retry_local_ad_failed_succeeds_with_password(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _raise_ad(*a, **k):
        raise RuntimeError("LDAP down")

    monkeypatch.setattr(local_ad_service, "create_user", _raise_ad)
    result = svc.provision(sqlite_session, _req())

    _stub_success_chain(monkeypatch)
    retried = svc.retry(sqlite_session, UUID(result.id), "NuevaP@ss1")

    assert retried.provisioning_status_name == "PendingEntraSync"


def test_retry_non_retryable_status_returns_unchanged(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_success_chain(monkeypatch, sync_status=EntraSyncStatus.SYNCED)
    result = svc.provision(sqlite_session, _req())
    assert result.provisioning_status_name in ("SyncedInEntra",)

    retried = svc.retry(sqlite_session, UUID(result.id), None)
    assert retried.provisioning_status_name == result.provisioning_status_name


def test_retry_license_failed_delegates_to_complete(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        provisioning_status_id=int(ProvisioningStatus.LICENSE_FAILED),
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.SYNCED, azure_object_id="a1"),
    )
    monkeypatch.setattr(
        license_service,
        "assign_employee_license",
        lambda session, upn, country="EC": LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number="SKU1", sku_id="x", message="ok"
        ),
    )

    result = svc.retry(sqlite_session, record.id, None)

    assert result.provisioning_status_name == "LicenseAssigned"


# ── complete / complete_pending ───────────────────────────────────────────────


def test_check_and_complete_not_found(sqlite_session) -> None:
    assert svc.check_and_complete_provisioning(sqlite_session, uuid4()) is None


def test_check_and_complete_license_assigned(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        provisioning_status_id=int(ProvisioningStatus.PENDING_ENTRA_SYNC),
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.SYNCED, azure_object_id="a1"),
    )
    monkeypatch.setattr(
        license_service,
        "assign_employee_license",
        lambda session, upn, country="EC": LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number="SKU1", sku_id="x", message="ok"
        ),
    )

    result = svc.check_and_complete_provisioning(sqlite_session, record.id)

    assert result.provisioning_status_name == "LicenseAssigned"
    assert result.license_sku_id == "SKU1"


def test_check_and_complete_license_failure(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        provisioning_status_id=int(ProvisioningStatus.SYNCED_IN_ENTRA),
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.SYNCED, azure_object_id="a1"),
    )
    monkeypatch.setattr(
        license_service,
        "assign_employee_license",
        lambda session, upn, country="EC": LicenseOperationResultRead(
            success=False, upn=upn, sku_part_number="SKU1", sku_id=None, message="sin cupos"
        ),
    )

    result = svc.check_and_complete_provisioning(sqlite_session, record.id)

    assert result.provisioning_status_name == "LicenseFailed"
    assert result.error_message == "sin cupos"


def test_check_and_complete_still_pending(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        provisioning_status_id=int(ProvisioningStatus.PENDING_ENTRA_SYNC),
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.PENDING_SYNC, message="aun no"),
    )

    result = svc.check_and_complete_provisioning(sqlite_session, record.id)

    assert result.provisioning_status_name == "PendingEntraSync"


def test_check_and_complete_already_final_status_noop(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        provisioning_status_id=int(ProvisioningStatus.LICENSE_ASSIGNED),
        provisioning_status_name="LicenseAssigned",
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    def _fail(*a, **k):
        raise AssertionError("no deberia llamarse")

    monkeypatch.setattr(azure_mgmt, "check_user_entra_sync", _fail)

    result = svc.check_and_complete_provisioning(sqlite_session, record.id)
    assert result.provisioning_status_name == "LicenseAssigned"


def test_complete_pending_empty(sqlite_session) -> None:
    result = svc.complete_pending(sqlite_session)
    assert result.total_processed == 0


def test_complete_pending_processes_all(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    sqlite_session.add_all(
        [
            UserProvisioning(
                hr_employee_id=1,
                email="a@uta.edu.ec",
                display_name="A",
                employee_type_id=1,
                provisioning_status_id=int(ProvisioningStatus.PENDING_ENTRA_SYNC),
            ),
            UserProvisioning(
                hr_employee_id=2,
                email="b@uta.edu.ec",
                display_name="B",
                employee_type_id=1,
                provisioning_status_id=int(ProvisioningStatus.LICENSE_FAILED),
            ),
        ]
    )
    sqlite_session.commit()

    monkeypatch.setattr(
        azure_mgmt,
        "check_user_entra_sync",
        lambda upn: EntraSyncResult(status=EntraSyncStatus.SYNCED, azure_object_id="a1"),
    )
    monkeypatch.setattr(
        license_service,
        "assign_employee_license",
        lambda session, upn, country="EC": LicenseOperationResultRead(
            success=True, upn=upn, sku_part_number="SKU1", sku_id="x", message="ok"
        ),
    )

    result = svc.complete_pending(sqlite_session)

    assert result.total_processed == 2
    assert result.license_assigned == 2


# ── reset_password ────────────────────────────────────────────────────────────


def test_reset_password_not_found(sqlite_session) -> None:
    assert svc.reset_password(sqlite_session, uuid4()) is None


def test_reset_password_without_ad_account_raises(sqlite_session) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    with pytest.raises(ValueError, match="no tiene cuenta en AD Local"):
        svc.reset_password(sqlite_session, record.id)


def test_reset_password_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    record = UserProvisioning(
        hr_employee_id=5,
        email="x@uta.edu.ec",
        display_name="X",
        employee_type_id=1,
        local_ad_object_id="guid-1",
    )
    sqlite_session.add(record)
    sqlite_session.commit()

    captured = {}
    monkeypatch.setattr(
        local_ad_service,
        "change_user_password",
        lambda ad_id, pw, force_password_change: captured.update(ad_id=ad_id, pw=pw),
    )

    result = svc.reset_password(sqlite_session, record.id)

    assert result.email == "x@uta.edu.ec"
    assert len(result.new_temporary_password) == 12
    assert captured["ad_id"] == "guid-1"


# ── disable ────────────────────────────────────────────────────────────────────


def test_disable_employee_no_active_account(sqlite_session) -> None:
    result = svc.disable_employee(sqlite_session, 999)
    assert result.success is False
    assert "cuenta activa" in result.error_message


def test_disable_employee_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    user_id = uuid4()
    sqlite_session.add(User(id=user_id, email="x@uta.edu.ec", is_active=True))
    sqlite_session.add(
        UserEmployee(
            user_id=user_id, employee_email="x@uta.edu.ec", hr_employee_id=5, is_active=True
        )
    )
    sqlite_session.add(
        UserProvisioning(
            hr_employee_id=5,
            email="x@uta.edu.ec",
            display_name="X",
            employee_type_id=1,
            local_ad_object_id="guid-1",
        )
    )
    sqlite_session.commit()

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

    result = svc.disable_employee(sqlite_session, 5)

    assert result.success is True
    assert ("enable", "guid-1", False) in calls
    assert ("move", "guid-1", "OU=Inactivos,DC=uta,DC=edu,DC=ec") in calls
    assert ("remove", "UActivos", "guid-1") in calls
    user = sqlite_session.get(User, user_id)
    assert user.is_active is False


def test_disable_employee_ad_failure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    user_id = uuid4()
    sqlite_session.add(User(id=user_id, email="x@uta.edu.ec", is_active=True))
    sqlite_session.add(
        UserEmployee(
            user_id=user_id, employee_email="x@uta.edu.ec", hr_employee_id=5, is_active=True
        )
    )
    sqlite_session.commit()

    def _raise(*a, **k):
        raise RuntimeError("AD caído")

    monkeypatch.setattr(local_ad_service, "set_user_enabled", _raise)

    result = svc.disable_employee(sqlite_session, 5)

    assert result.success is False
    assert "AD caído" in result.error_message


def test_disable_by_provisioning_id_not_found(sqlite_session) -> None:
    assert svc.disable_by_provisioning_id(sqlite_session, uuid4()) is None


def test_disable_by_ad_id_not_found(sqlite_session) -> None:
    assert svc.disable_by_ad_id(sqlite_session, "no-existe") is None


def test_disable_by_ad_id_empty_returns_none(sqlite_session) -> None:
    assert svc.disable_by_ad_id(sqlite_session, "") is None
