import uuid

import pytest
from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult

from repositoryuta.config import get_settings
from repositoryuta.core.exceptions import BusinessValidationError, ConflictError, NotFoundError
from repositoryuta.services import local_ad_service


class _FakeMicrosoftExtension:
    def __init__(self, calls: list[tuple[str, str]]) -> None:
        self._calls = calls

    def modify_password(self, dn, new_password, old_password=None):
        self._calls.append((dn, new_password))
        return True


class _FakeExtend:
    def __init__(self, calls: list[tuple[str, str]]) -> None:
        self.microsoft = _FakeMicrosoftExtension(calls)


class _FakeConnection:
    def __init__(
        self, responses: list[list[dict]], *, fail_add_cns: set[str] | None = None
    ) -> None:
        self._responses = responses
        self.response: list[dict] = []
        self.unbound = False
        self._fail_add_cns = fail_add_cns or set()
        self.add_calls: list[tuple[str, dict]] = []
        self.modify_calls: list[tuple[str, dict]] = []
        self.delete_calls: list[str] = []
        self.modify_dn_calls: list[tuple[str, str, str | None]] = []
        self.password_calls: list[tuple[str, str]] = []
        self.extend = _FakeExtend(self.password_calls)

    def search(self, base_dn, ldap_filter, scope, attributes):
        self.response = self._responses.pop(0) if self._responses else []
        return True

    def add(self, dn, object_class=None, attributes=None, controls=None):
        cn = attributes.get("cn") if attributes else None
        if cn in self._fail_add_cns:
            raise LDAPEntryAlreadyExistsResult("entry already exists")
        self.add_calls.append((dn, attributes or {}))
        return True

    def modify(self, dn, changes, controls=None):
        self.modify_calls.append((dn, changes))
        return True

    def delete(self, dn, controls=None):
        self.delete_calls.append(dn)
        return True

    def modify_dn(self, dn, relative_dn, delete_old_dn=True, new_superior=None, controls=None):
        self.modify_dn_calls.append((dn, relative_dn, new_superior))
        return True

    def unbind(self) -> None:
        self.unbound = True


def _user_entry(*, guid: uuid.UUID, mail: str, display_name: str, uac: str = "512") -> dict:
    return {
        "type": "searchResEntry",
        "dn": f"CN={display_name},DC=uta,DC=edu,DC=ec",
        "raw_attributes": {"objectGUID": [guid.bytes_le]},
        "attributes": {
            "mail": [mail],
            "userPrincipalName": [mail],
            "displayName": [display_name],
            "userAccountControl": [uac],
        },
    }


def _group_entry(*, guid: uuid.UUID, cn: str) -> dict:
    return {
        "type": "searchResEntry",
        "dn": f"CN={cn},DC=uta,DC=edu,DC=ec",
        "raw_attributes": {"objectGUID": [guid.bytes_le]},
        "attributes": {"cn": [cn]},
    }


def _referral_entry() -> dict:
    """Espejo de una respuesta LDAP searchResRef (referencia entre particiones
    del AD) — el .NET real (System.DirectoryServices.Protocols) las filtra
    fuera de SearchResponse.Entries automaticamente."""
    return {"type": "searchResRef"}


@pytest.fixture(autouse=True)
def _configure_local_ad(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOCAL_AD__SERVER", "dc01.uta.edu.ec")
    monkeypatch.setenv("LOCAL_AD__BASE_DN", "DC=uta,DC=edu,DC=ec")
    monkeypatch.setenv("LOCAL_AD__SERVICE_ACCOUNT_DN", "ut4segad")
    monkeypatch.setenv("LOCAL_AD__SERVICE_ACCOUNT_PASSWORD", "secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_bind_credentials_builds_upn_from_base_dn_for_plain_username() -> None:
    opts = get_settings().local_ad
    bind_user, _auth_type, domain = local_ad_service._bind_credentials(opts)
    assert bind_user == "ut4segad@uta.edu.ec"
    assert domain == "uta.edu.ec"


def test_find_user_by_email_returns_none_when_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.find_user_by_email("nadie@uta.edu.ec")

    assert result is None
    assert conn.unbound is True


def test_find_user_by_email_maps_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    guid = uuid.uuid4()
    conn = _FakeConnection(
        responses=[[_user_entry(guid=guid, mail="juan@uta.edu.ec", display_name="Juan Perez")]]
    )
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.find_user_by_email("juan@uta.edu.ec")

    assert result is not None
    assert result.id == str(guid)
    assert result.email == "juan@uta.edu.ec"
    assert result.display_name == "Juan Perez"
    assert result.is_enabled is True


def test_get_user_groups_returns_empty_when_user_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.get_user_groups(str(uuid.uuid4()))

    assert result == []


def test_get_user_groups_maps_entries(monkeypatch: pytest.MonkeyPatch) -> None:
    user_guid = uuid.uuid4()
    group_guid = uuid.uuid4()
    dn_lookup_response = [
        {"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}
    ]
    groups_response = [_group_entry(guid=group_guid, cn="Docentes")]
    conn = _FakeConnection(responses=[dn_lookup_response, groups_response])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.get_user_groups(str(user_guid))

    assert len(result) == 1
    assert result[0].name == "Docentes"
    assert result[0].id == str(group_guid)


def test_get_user_groups_filters_out_ldap_referrals(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regresion: una busqueda que cruza limites de particion del AD devuelve
    referencias (searchResRef) mezcladas con las entradas reales — deben
    descartarse, no mapearse como grupos vacios (bug real encontrado probando
    contra el AD de produccion, 2026-08-27)."""
    user_guid = uuid.uuid4()
    group_guid = uuid.uuid4()
    dn_lookup_response = [
        {"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}
    ]
    groups_response = [
        _group_entry(guid=group_guid, cn="Docentes"),
        _referral_entry(),
        _referral_entry(),
    ]
    conn = _FakeConnection(responses=[dn_lookup_response, groups_response])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.get_user_groups(str(user_guid))

    assert len(result) == 1
    assert result[0].name == "Docentes"


# ── get_user / list_users ────────────────────────────────────────────────────


def test_get_user_returns_none_when_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    assert local_ad_service.get_user(str(uuid.uuid4())) is None


def test_list_users_paginates_client_side(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [
        _user_entry(guid=uuid.uuid4(), mail=f"user{i}@uta.edu.ec", display_name=f"User {i}")
        for i in range(5)
    ]
    conn = _FakeConnection(responses=[entries])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    page1 = local_ad_service.list_users(page=1, page_size=2)
    assert [u.display_name for u in page1] == ["User 0", "User 1"]


# ── create_user ───────────────────────────────────────────────────────────────


def _new_user(
    email="nuevo@uta.edu.ec", display_name="Nuevo Usuario", id_card=None
) -> local_ad_service.DirectoryUser:
    return local_ad_service.DirectoryUser(
        id="",
        email=email,
        display_name=display_name,
        given_name="Nuevo",
        surname="Usuario",
        job_title=None,
        department=None,
        is_enabled=True,
        id_card=id_card,
    )


def test_create_user_requires_target_ou() -> None:
    with pytest.raises(BusinessValidationError):
        local_ad_service.create_user(_new_user(), "P@ssw0rd1", "")


def test_create_user_rejects_duplicate(monkeypatch: pytest.MonkeyPatch) -> None:
    existing = _user_entry(guid=uuid.uuid4(), mail="nuevo@uta.edu.ec", display_name="Ya Existe")
    conn = _FakeConnection(responses=[[existing]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(ConflictError):
        local_ad_service.create_user(_new_user(), "P@ssw0rd1", "OU=Activos,DC=uta,DC=edu,DC=ec")


def test_create_user_success_sets_password_and_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    created_guid = uuid.uuid4()
    created_entry = _user_entry(
        guid=created_guid, mail="nuevo@uta.edu.ec", display_name="Nuevo Usuario"
    )
    conn = _FakeConnection(responses=[[], [created_entry]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    password_conn = _FakeConnection(responses=[])
    monkeypatch.setattr(local_ad_service, "_build_password_connection", lambda: password_conn)

    result = local_ad_service.create_user(
        _new_user(), "P@ssw0rd1", "OU=Activos,DC=uta,DC=edu,DC=ec"
    )

    assert result.email == "nuevo@uta.edu.ec"
    assert len(conn.add_calls) == 1
    assert password_conn.password_calls == [(conn.add_calls[0][0], "P@ssw0rd1")]
    modified_attrs = {frozenset(attrs.keys()) for _dn, attrs in conn.modify_calls}
    assert any("userAccountControl" in attrs for attrs in modified_attrs)
    assert any("pwdLastSet" in attrs for attrs in modified_attrs)


def test_create_user_writes_employee_id_when_id_card_provided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Espejo de LocalAdDirectoryService.CreateUserAsync: persiste la cedula
    como atributo employeeID (usado por el flujo de aprovisionamiento)."""
    created_guid = uuid.uuid4()
    created_entry = _user_entry(
        guid=created_guid, mail="nuevo@uta.edu.ec", display_name="Nuevo Usuario"
    )
    conn = _FakeConnection(responses=[[], [created_entry]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)
    monkeypatch.setattr(
        local_ad_service, "_build_password_connection", lambda: _FakeConnection(responses=[])
    )

    local_ad_service.create_user(
        _new_user(id_card="1234567890"), "P@ssw0rd1", "OU=Activos,DC=uta,DC=edu,DC=ec"
    )

    _dn, attrs = conn.add_calls[0]
    assert attrs["employeeID"] == "1234567890"


def test_create_user_retries_with_numeric_suffix_on_cn_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_entry = _user_entry(
        guid=uuid.uuid4(), mail="nuevo@uta.edu.ec", display_name="Nuevo Usuario"
    )
    conn = _FakeConnection(responses=[[], [created_entry]], fail_add_cns={"Nuevo Usuario"})
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)
    monkeypatch.setattr(
        local_ad_service, "_build_password_connection", lambda: _FakeConnection(responses=[])
    )

    result = local_ad_service.create_user(
        _new_user(), "P@ssw0rd1", "OU=Activos,DC=uta,DC=edu,DC=ec"
    )

    assert result.cn_warning is not None
    assert len(conn.add_calls) == 1
    assert conn.add_calls[0][1]["cn"] == "Nuevo Usuario 1"


# ── update_user / set_user_enabled / delete_user / move_user_to_ou ──────────


def test_update_user_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.update_user(str(uuid.uuid4()), _new_user())


def test_update_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    updated_entry = _user_entry(guid=uuid.uuid4(), mail="juan@uta.edu.ec", display_name="Juan P.")
    conn = _FakeConnection(responses=[dn_lookup, [updated_entry]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.update_user(str(uuid.uuid4()), _new_user(display_name="Juan P."))

    assert result.display_name == "Juan P."
    assert len(conn.modify_calls) == 1


def test_set_user_enabled_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.set_user_enabled(str(uuid.uuid4()), True)


def test_set_user_enabled_toggles_uac(monkeypatch: pytest.MonkeyPatch) -> None:
    dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    conn = _FakeConnection(responses=[dn_lookup])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    local_ad_service.set_user_enabled(str(uuid.uuid4()), False)

    _dn, changes = conn.modify_calls[0]
    assert changes["userAccountControl"][0][1] == ["514"]


def test_delete_user_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.delete_user(str(uuid.uuid4()))


def test_delete_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    conn = _FakeConnection(responses=[dn_lookup])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    local_ad_service.delete_user(str(uuid.uuid4()))

    assert conn.delete_calls == ["CN=Juan Perez,DC=uta,DC=edu,DC=ec"]


def test_move_user_to_ou_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.move_user_to_ou(str(uuid.uuid4()), "OU=Inactivos,DC=uta,DC=edu,DC=ec")


def test_move_user_to_ou_success(monkeypatch: pytest.MonkeyPatch) -> None:
    dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    conn = _FakeConnection(responses=[dn_lookup])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    local_ad_service.move_user_to_ou(str(uuid.uuid4()), "OU=Inactivos,DC=uta,DC=edu,DC=ec")

    dn, rdn, new_superior = conn.modify_dn_calls[0]
    assert dn == "CN=Juan Perez,DC=uta,DC=edu,DC=ec"
    assert rdn == "CN=Juan Perez"
    assert new_superior == "OU=Inactivos,DC=uta,DC=edu,DC=ec"


# ── change_user_password ─────────────────────────────────────────────────────


def test_change_user_password_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.change_user_password(str(uuid.uuid4()), "NewP@ss1")


def test_change_user_password_success(monkeypatch: pytest.MonkeyPatch) -> None:
    dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    conns = iter([_FakeConnection(responses=[dn_lookup]), _FakeConnection(responses=[])])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: next(conns))
    password_conn = _FakeConnection(responses=[])
    monkeypatch.setattr(local_ad_service, "_build_password_connection", lambda: password_conn)

    local_ad_service.change_user_password(str(uuid.uuid4()), "NewP@ss1")

    assert password_conn.password_calls == [("CN=Juan Perez,DC=uta,DC=edu,DC=ec", "NewP@ss1")]


# ── grupos ────────────────────────────────────────────────────────────────────


def test_get_group_returns_none_when_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    assert local_ad_service.get_group(str(uuid.uuid4())) is None


def test_list_groups_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    entries = [_group_entry(guid=uuid.uuid4(), cn=f"Grupo{i}") for i in range(3)]
    conn = _FakeConnection(responses=[entries])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.list_groups(page=1, page_size=2)

    assert [g.name for g in result] == ["Grupo0", "Grupo1"]


def test_create_group_success(monkeypatch: pytest.MonkeyPatch) -> None:
    created = _group_entry(guid=uuid.uuid4(), cn="NuevoGrupo")
    conn = _FakeConnection(responses=[[created]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    result = local_ad_service.create_group("NuevoGrupo", "Descripcion")

    assert result.name == "NuevoGrupo"
    assert conn.add_calls[0][1]["cn"] == "NuevoGrupo"


def test_add_user_to_group_not_found_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    with pytest.raises(NotFoundError):
        local_ad_service.add_user_to_group("Docentes", str(uuid.uuid4()))


def test_add_and_remove_user_from_group(monkeypatch: pytest.MonkeyPatch) -> None:
    group_dn_lookup = [{"type": "searchResEntry", "dn": "CN=Docentes,DC=uta,DC=edu,DC=ec"}]
    user_dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    conn = _FakeConnection(responses=[group_dn_lookup, user_dn_lookup])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    local_ad_service.add_user_to_group("Docentes", str(uuid.uuid4()))

    _dn, changes = conn.modify_calls[0]
    assert changes["member"][0][1] == ["CN=Juan Perez,DC=uta,DC=edu,DC=ec"]


def test_is_user_in_group_true(monkeypatch: pytest.MonkeyPatch) -> None:
    group_dn_lookup = [{"type": "searchResEntry", "dn": "CN=Docentes,DC=uta,DC=edu,DC=ec"}]
    user_dn_lookup = [{"type": "searchResEntry", "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec"}]
    member_search = [
        {
            "type": "searchResEntry",
            "dn": "CN=Docentes,DC=uta,DC=edu,DC=ec",
            "attributes": {"member": ["CN=Juan Perez,DC=uta,DC=edu,DC=ec"]},
        }
    ]
    conn = _FakeConnection(responses=[group_dn_lookup, user_dn_lookup, member_search])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    assert local_ad_service.is_user_in_group("Docentes", str(uuid.uuid4())) is True


def test_is_user_in_group_false_when_group_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _FakeConnection(responses=[[]])
    monkeypatch.setattr(local_ad_service, "_build_connection", lambda: conn)

    assert local_ad_service.is_user_in_group("Docentes", str(uuid.uuid4())) is False


# ── authenticate_user ─────────────────────────────────────────────────────────


class _FakeAuthConnection(_FakeConnection):
    def __init__(self, responses, *, should_fail: bool = False) -> None:
        super().__init__(responses)
        self._should_fail = should_fail

    def bind(self) -> None:
        if self._should_fail:
            raise RuntimeError("80090308: LdapErr invalidCredentials")


def test_authenticate_user_invalid_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "Connection",
        lambda *a, **k: _FakeAuthConnection(responses=[], should_fail=True),
    )

    result = local_ad_service.authenticate_user("juan", "wrong")

    assert result.success is False
    assert result.failure_reason == "Invalid credentials"


def test_authenticate_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = [
        {
            "type": "searchResEntry",
            "dn": "CN=Juan Perez,DC=uta,DC=edu,DC=ec",
            "attributes": {"displayName": ["Juan Perez"], "mail": ["juan@uta.edu.ec"]},
        }
    ]
    fake_conn = _FakeAuthConnection(responses=[entry])
    monkeypatch.setattr(local_ad_service, "Connection", lambda *a, **k: fake_conn)

    result = local_ad_service.authenticate_user("juan", "correct")

    assert result.success is True
    assert result.email == "juan@uta.edu.ec"
    assert result.display_name == "Juan Perez"
