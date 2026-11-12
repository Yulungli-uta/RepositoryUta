from uuid import UUID, uuid4

import pytest

from repositoryuta.models.audit import AuditLog, AzureSyncLog
from repositoryuta.models.identity import User
from repositoryuta.schemas.azure_management import (
    CreateAzureGroupRequest,
    CreateAzureUserRequest,
    UpdateAzureGroupRequest,
    UpdateAzureUserRequest,
)
from repositoryuta.services import azure_management_service as svc


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if not self.ok:
            raise Exception(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


def _patch_graph(monkeypatch: pytest.MonkeyPatch, responder) -> list[tuple]:
    calls: list[tuple] = []

    def _fake(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return responder(method, path, kwargs)

    monkeypatch.setattr(svc, "graph_request", _fake)
    return calls


# ── validate_password_policy / generate_secure_password ─────────────────────


def test_validate_password_policy_rejects_empty() -> None:
    result = svc.validate_password_policy("")
    assert result.is_valid is False
    assert result.strength_level == "Muy débil"


def test_validate_password_policy_strong_password() -> None:
    result = svc.validate_password_policy("Sup3r$ecurePass!")
    assert result.is_valid is True
    assert result.strength_level in ("Fuerte", "Muy fuerte")


def test_generate_secure_password_meets_policy() -> None:
    password = svc.generate_secure_password()
    assert len(password) == 16
    assert svc.validate_password_policy(password).is_valid is True


# ── usuarios ──────────────────────────────────────────────────────────────────


def _create_user_dto(**overrides) -> CreateAzureUserRequest:
    defaults = dict(
        email="nuevo@uta.edu.ec",
        display_name="Nuevo Usuario",
        given_name="Nuevo",
        surname="Usuario",
        password="Sup3r$ecurePass!",
    )
    defaults.update(overrides)
    return CreateAzureUserRequest(**defaults)


def test_create_user_in_azure_rejects_invalid_email(sqlite_session) -> None:
    with pytest.raises(ValueError, match="Email inválido"):
        svc.create_user_in_azure(sqlite_session, _create_user_dto(email="not-an-email"))


def test_create_user_in_azure_rejects_weak_password(sqlite_session) -> None:
    with pytest.raises(ValueError, match="política"):
        svc.create_user_in_azure(sqlite_session, _create_user_dto(password="weak"))


def test_create_user_in_azure_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())

    def _responder(method, path, kwargs):
        assert method == "POST"
        assert path == "/users"
        return _FakeResponse(
            201,
            {
                "id": azure_id,
                "userPrincipalName": "nuevo@uta.edu.ec",
                "displayName": "Nuevo Usuario",
                "accountEnabled": True,
            },
        )

    _patch_graph(monkeypatch, _responder)

    result = svc.create_user_in_azure(sqlite_session, _create_user_dto())

    assert result.id == azure_id
    assert result.email == "nuevo@uta.edu.ec"
    assert sqlite_session.query(User).filter_by(azure_object_id=UUID(azure_id)).count() == 1
    assert sqlite_session.query(AzureSyncLog).filter_by(sync_type="UserCreated").count() == 1
    assert sqlite_session.query(AuditLog).filter_by(action="CreateAzureUser").count() == 1


def test_get_user_from_azure_not_found_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(404))

    assert svc.get_user_from_azure(str(uuid4())) is None


def test_get_user_from_azure_success(monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(
            200, {"id": azure_id, "userPrincipalName": "juan@uta.edu.ec", "displayName": "Juan"}
        ),
    )

    result = svc.get_user_from_azure(azure_id)

    assert result is not None
    assert result.email == "juan@uta.edu.ec"


def test_get_user_from_azure_escapes_id_in_graph_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """A diferencia del SDK .NET (que escapa los segmentos de sus builders
    fluent automaticamente), aqui la URL se arma a mano con f-strings — sin
    encode_path_segment, un id con '/' alteraria la ruta real enviada a
    Graph (ver graph_client.encode_path_segment)."""
    calls = _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"id": "x"}))

    svc.get_user_from_azure("a/subscribedSkus")

    assert calls[0][1] == "/users/a%2FsubscribedSkus"


def test_get_user_by_email_from_azure_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"value": []}))

    assert svc.get_user_by_email_from_azure("nadie@uta.edu.ec") is None


def test_update_user_in_azure_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())
    calls = []

    def _responder(method, path, kwargs):
        calls.append(method)
        if method == "PATCH":
            return _FakeResponse(200)
        return _FakeResponse(
            200, {"id": azure_id, "userPrincipalName": "juan@uta.edu.ec", "displayName": "Juan P."}
        )

    _patch_graph(monkeypatch, _responder)

    result = svc.update_user_in_azure(
        sqlite_session, azure_id, UpdateAzureUserRequest(display_name="Juan P.")
    )

    assert result is not None
    assert result.display_name == "Juan P."
    assert sqlite_session.query(AuditLog).filter_by(action="UpdateAzureUser").count() == 1


def test_enable_disable_user_in_azure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200))

    assert svc.enable_disable_user_in_azure(sqlite_session, azure_id, False) is True
    assert sqlite_session.query(AuditLog).filter_by(action="DisableAzureUser").count() == 1


def test_delete_user_from_azure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(204))

    assert svc.delete_user_from_azure(sqlite_session, azure_id) is True
    assert sqlite_session.query(AuditLog).filter_by(action="DeleteAzureUser").count() == 1


def test_list_users_from_azure_paginates_via_next_link(monkeypatch: pytest.MonkeyPatch) -> None:
    page1 = {
        "@odata.count": 3,
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skip=1",
        "value": [{"id": "1", "userPrincipalName": "a@uta.edu.ec", "displayName": "A"}],
    }
    page2 = {"value": [{"id": "2", "userPrincipalName": "b@uta.edu.ec", "displayName": "B"}]}

    def _responder(method, path, kwargs):
        if "skip" in path:
            return _FakeResponse(200, page2)
        return _FakeResponse(200, page1)

    _patch_graph(monkeypatch, _responder)

    result = svc.list_users_from_azure(page=2, page_size=1)

    assert result.total_count == 3
    assert result.items[0].id == "2"


# ── contraseñas ──────────────────────────────────────────────────────────────


def test_reset_password_in_azure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    azure_id = str(uuid4())
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200))

    new_password = svc.reset_password_in_azure(sqlite_session, azure_id)

    assert len(new_password) == 16
    assert sqlite_session.query(AuditLog).filter_by(action="ResetPasswordAzureUser").count() == 1


def test_change_password_in_azure_rejects_weak_password(sqlite_session) -> None:
    with pytest.raises(ValueError, match="política"):
        svc.change_password_in_azure(sqlite_session, str(uuid4()), "weak")


def test_change_password_in_azure_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200))

    assert svc.change_password_in_azure(sqlite_session, str(uuid4()), "Sup3r$ecurePass!") is True


# ── roles ────────────────────────────────────────────────────────────────────


def test_get_all_azure_directory_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(
            200, {"value": [{"id": "r1", "displayName": "Global Admin"}]}
        ),
    )

    roles = svc.get_all_azure_directory_roles()

    assert roles[0].display_name == "Global Admin"
    assert roles[0].is_built_in is True


def test_assign_and_remove_azure_role(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200))

    assert svc.assign_azure_role(sqlite_session, "user-id", "role-id") is True
    assert svc.remove_azure_role(sqlite_session, "user-id", "role-id") is True
    assert sqlite_session.query(AuditLog).filter_by(action="AssignAzureRole").count() == 1
    assert sqlite_session.query(AuditLog).filter_by(action="RemoveAzureRole").count() == 1


# ── grupos ────────────────────────────────────────────────────────────────────


def test_create_group_in_azure_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    group_id = str(uuid4())
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(
            201, {"id": group_id, "displayName": "NuevoGrupo", "groupTypes": []}
        ),
    )

    result = svc.create_group_in_azure(
        sqlite_session, CreateAzureGroupRequest(display_name="NuevoGrupo")
    )

    assert result.id == group_id
    assert result.group_type == "Security"
    assert sqlite_session.query(AuditLog).filter_by(action="CreateAzureGroup").count() == 1


def test_get_group_from_azure_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(404))

    assert svc.get_group_from_azure(str(uuid4())) is None


def test_update_group_in_azure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    group_id = str(uuid4())

    def _responder(method, path, kwargs):
        if method == "PATCH":
            return _FakeResponse(200)
        if "members" in path:
            return _FakeResponse(200, {"value": []})
        return _FakeResponse(200, {"id": group_id, "displayName": "Actualizado", "groupTypes": []})

    _patch_graph(monkeypatch, _responder)

    result = svc.update_group_in_azure(
        sqlite_session, group_id, UpdateAzureGroupRequest(display_name="Actualizado")
    )

    assert result is not None
    assert result.display_name == "Actualizado"


def test_delete_group_from_azure(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(204))

    assert svc.delete_group_from_azure(sqlite_session, str(uuid4())) is True


def test_add_and_remove_user_from_azure_group(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200))

    assert svc.add_user_to_azure_group(sqlite_session, "group-id", "user-id") is True
    assert svc.remove_user_from_azure_group(sqlite_session, "group-id", "user-id") is True


def test_get_user_azure_groups_filters_by_rol_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(
        monkeypatch,
        lambda m, p, k: _FakeResponse(
            200,
            {
                "value": [
                    {"id": "1", "displayName": "Rol_Docente", "groupTypes": []},
                    {"id": "2", "displayName": "Otro Grupo", "groupTypes": []},
                ]
            },
        ),
    )

    groups = svc.get_user_azure_groups(str(uuid4()))

    assert len(groups) == 1
    assert groups[0].display_name == "Rol_Docente"


# ── operaciones masivas ───────────────────────────────────────────────────────


def test_bulk_create_users_reports_failures(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        svc,
        "create_user_in_azure",
        lambda session, dto: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    result = svc.bulk_create_users(sqlite_session, [_create_user_dto()])

    assert result.total_requested == 1
    assert result.failed == 1
    assert result.errors[0].error_code == "CREATE_FAILED"


def test_bulk_add_users_to_group(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "add_user_to_azure_group", lambda session, g, u: u != "bad")

    result = svc.bulk_add_users_to_group(sqlite_session, "group-id", ["good", "bad"])

    assert result.successful == 1
    assert result.failed == 1


# ── sync ─────────────────────────────────────────────────────────────────────


def test_sync_user_to_local_db_user_not_found(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(svc, "get_user_from_azure", lambda azure_object_id: None)

    result = svc.sync_user_to_local_db(sqlite_session, str(uuid4()))

    assert result.success is False
    assert result.users_failed == 1


def test_sync_user_to_local_db_creates_new_user(
    sqlite_session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from repositoryuta.schemas.azure_management import AzureUserRead

    azure_id = str(uuid4())
    monkeypatch.setattr(
        svc,
        "get_user_from_azure",
        lambda azure_object_id: AzureUserRead(
            id=azure_id,
            email="nuevo@uta.edu.ec",
            display_name="Nuevo",
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
        ),
    )

    result = svc.sync_user_to_local_db(sqlite_session, azure_id)

    assert result.success is True
    assert result.users_created == 1
    assert sqlite_session.query(User).filter_by(azure_object_id=UUID(azure_id)).count() == 1


# ── check_user_entra_sync (ya existente antes del refactor) ──────────────────


def test_check_user_entra_sync_pending_when_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"value": []}))

    result = svc.check_user_entra_sync("nadie@uta.edu.ec")

    assert result.status == svc.EntraSyncStatus.PENDING_SYNC


def test_check_user_entra_sync_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"value": [{"id": "azure-id", "accountEnabled": True}]}
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    result = svc.check_user_entra_sync("juan@uta.edu.ec")

    assert result.status == svc.EntraSyncStatus.SYNCED
    assert result.account_enabled is True
    assert result.azure_object_id == "azure-id"


def test_check_user_entra_sync_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"value": [{"id": "azure-id", "accountEnabled": False}]}
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    result = svc.check_user_entra_sync("juan@uta.edu.ec")

    assert result.status == svc.EntraSyncStatus.DISABLED


def test_check_user_entra_sync_handles_graph_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(500, {}))

    result = svc.check_user_entra_sync("juan@uta.edu.ec")

    assert result.status == svc.EntraSyncStatus.SYNC_ERROR


def test_check_user_entra_sync_escapes_quotes_in_upn(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, {"value": []}))

    svc.check_user_entra_sync("o'brien@uta.edu.ec")

    _method, _path, kwargs = calls[0]
    assert "o''brien@uta.edu.ec" in kwargs["params"]["$filter"]


# ── cobertura adicional: grupos/roles de solo lectura ────────────────────────


def test_get_group_from_azure_success(monkeypatch: pytest.MonkeyPatch) -> None:
    group_id = str(uuid4())

    def _responder(method, path, kwargs):
        if "members" in path:
            return _FakeResponse(200, {"value": [{"id": "u1"}, {"id": "u2"}]})
        return _FakeResponse(
            200, {"id": group_id, "displayName": "Docentes", "groupTypes": ["Unified"]}
        )

    _patch_graph(monkeypatch, _responder)

    result = svc.get_group_from_azure(group_id)

    assert result is not None
    assert result.member_count == 2
    assert result.group_type == "Microsoft365"


def test_list_groups_from_azure(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "@odata.count": 1,
        "value": [{"id": "g1", "displayName": "Docentes", "groupTypes": []}],
    }
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    result = svc.list_groups_from_azure(page=1, page_size=10)

    assert result.total_count == 1
    assert result.items[0].display_name == "Docentes"


def test_get_group_members(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "value": [
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "u1",
                "userPrincipalName": "a@uta.edu.ec",
            },
            {"@odata.type": "#microsoft.graph.group", "id": "g1"},
        ]
    }
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    members = svc.get_group_members("group-id")

    assert len(members) == 1
    assert members[0].id == "u1"


def test_get_role_members(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "value": [
            {
                "@odata.type": "#microsoft.graph.user",
                "id": "u1",
                "userPrincipalName": "a@uta.edu.ec",
            },
        ]
    }
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    members = svc.get_role_members("role-id")

    assert len(members) == 1


def test_get_user_azure_roles_maps_groups_and_directory_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "value": [
            {"@odata.type": "#microsoft.graph.group", "id": "g1", "displayName": "Rol_Docente"},
            {
                "@odata.type": "#microsoft.graph.directoryRole",
                "id": "r1",
                "displayName": "Global Admin",
            },
        ]
    }
    _patch_graph(monkeypatch, lambda m, p, k: _FakeResponse(200, payload))

    roles = svc.get_user_azure_roles(str(uuid4()))

    assert len(roles) == 2
    assert {r.is_built_in for r in roles} == {True, False}


def test_bulk_create_users_success(sqlite_session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "create_user_in_azure", lambda session, dto: None)

    users = [_create_user_dto(), _create_user_dto(email="otro@uta.edu.ec")]
    result = svc.bulk_create_users(sqlite_session, users)

    assert result.total_requested == 2
    assert result.successful == 2
    assert result.failed == 0
