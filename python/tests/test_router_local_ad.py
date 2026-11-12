import uuid

import pytest

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.services import azure_management_service, local_ad_service


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid.uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _stub_entra_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ningun test de este router necesita probar Graph de verdad — se
    stubea check_user_entra_sync para aislar el comportamiento de LocalAd."""
    monkeypatch.setattr(
        azure_management_service,
        "check_user_entra_sync",
        lambda upn: azure_management_service.EntraSyncResult(
            status=azure_management_service.EntraSyncStatus.UNKNOWN, message="stub"
        ),
    )


def _sample_user(**overrides) -> local_ad_service.DirectoryUser:
    defaults = dict(
        id=str(uuid.uuid4()),
        email="juan@uta.edu.ec",
        display_name="Juan Perez",
        given_name="Juan",
        surname="Perez",
        job_title=None,
        department=None,
        is_enabled=True,
    )
    defaults.update(overrides)
    return local_ad_service.DirectoryUser(**defaults)


def _sample_group(**overrides) -> local_ad_service.DirectoryGroup:
    defaults = dict(id=str(uuid.uuid4()), name="Docentes", description=None, email=None)
    defaults.update(overrides)
    return local_ad_service.DirectoryGroup(**defaults)


def test_authenticate_invalid_credentials_returns_401(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "authenticate_user",
        lambda u, p: local_ad_service.AuthResult(
            success=False, email=None, display_name=None, failure_reason="Invalid credentials"
        ),
    )

    response = client.post(
        "/api/local-ad/authenticate", json={"username": "juan", "password": "wrong"}
    )

    assert response.status_code == 401


def test_authenticate_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service,
        "authenticate_user",
        lambda u, p: local_ad_service.AuthResult(
            success=True, email="juan@uta.edu.ec", display_name="Juan Perez"
        ),
    )

    response = client.post(
        "/api/local-ad/authenticate", json={"username": "juan", "password": "correct"}
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "juan@uta.edu.ec"


def test_get_user_by_email_not_found_returns_404(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "find_user_by_email", lambda email: None)

    response = client.get("/api/local-ad/users/by-email/nadie@uta.edu.ec", headers=_admin_header())

    assert response.status_code == 404


def test_get_user_by_email_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service, "find_user_by_email", lambda email: _sample_user(email=email)
    )

    response = client.get("/api/local-ad/users/by-email/juan@uta.edu.ec", headers=_admin_header())

    assert response.status_code == 200
    assert response.json()["data"]["accountEnabled"] is True


def test_get_user_groups(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service, "get_user_groups", lambda user_id: [_sample_group()]
    )

    response = client.get(
        f"/api/local-ad/users/{uuid.uuid4()}/groups", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"][0]["name"] == "Docentes"


def test_is_user_in_group(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "is_user_in_group", lambda g, u: True)

    response = client.get(
        f"/api/local-ad/users/{uuid.uuid4()}/groups/{uuid.uuid4()}", headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["isMember"] is True


def test_get_user_not_found_returns_404(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "get_user", lambda object_id: None)

    response = client.get(f"/api/local-ad/users/{uuid.uuid4()}", headers=_admin_header())

    assert response.status_code == 404


def test_create_user_requires_given_name(client) -> None:
    response = client.post(
        "/api/local-ad/users",
        json={
            "email": "nuevo@uta.edu.ec",
            "displayName": "Nuevo Usuario",
            "initialPassword": "P@ssw0rd1",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 400


def test_create_user_enforces_institutional_domain(client, monkeypatch: pytest.MonkeyPatch) -> None:
    from repositoryuta.config import get_settings

    monkeypatch.setattr(get_settings().local_ad, "base_dn", "DC=uta,DC=edu,DC=ec")

    response = client.post(
        "/api/local-ad/users",
        json={
            "email": "nuevo@gmail.com",
            "displayName": "Nuevo Usuario",
            "givenName": "Nuevo",
            "surname": "Usuario",
            "initialPassword": "P@ssw0rd1",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 400


def test_create_user_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    from repositoryuta.config import get_settings

    monkeypatch.setattr(get_settings().local_ad, "base_dn", "DC=uta,DC=edu,DC=ec")
    monkeypatch.setattr(
        get_settings().local_ad, "funcionarios_activos_ou", "OU=Activos,DC=uta,DC=edu,DC=ec"
    )
    monkeypatch.setattr(
        local_ad_service,
        "create_user",
        lambda user, pwd, ou, force: _sample_user(email=user.email),
    )

    response = client.post(
        "/api/local-ad/users",
        json={
            "email": "nuevo@uta.edu.ec",
            "displayName": "Nuevo Usuario",
            "givenName": "Nuevo",
            "surname": "Usuario",
            "initialPassword": "P@ssw0rd1",
        },
        headers=_admin_header(),
    )

    assert response.status_code == 200
    assert response.json()["data"]["email"] == "nuevo@uta.edu.ec"
    assert response.json()["data"]["entraSync"]["status"] == "Unknown"


def test_delete_user_not_found_returns_404(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "get_user", lambda object_id: None)

    response = client.delete(f"/api/local-ad/users/{uuid.uuid4()}", headers=_admin_header())

    assert response.status_code == 404


def test_delete_user_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_ad_service, "get_user", lambda object_id: _sample_user())
    deleted_ids = []
    monkeypatch.setattr(local_ad_service, "delete_user", lambda oid: deleted_ids.append(oid))

    response = client.delete(f"/api/local-ad/users/{uuid.uuid4()}", headers=_admin_header())

    assert response.status_code == 200
    assert len(deleted_ids) == 1


def test_create_group_requires_name(client) -> None:
    response = client.post("/api/local-ad/groups", json={"groupName": ""}, headers=_admin_header())
    assert response.status_code == 400


def test_create_group_success(client, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        local_ad_service, "create_group", lambda name, desc: _sample_group(name=name)
    )

    response = client.post(
        "/api/local-ad/groups", json={"groupName": "NuevoGrupo"}, headers=_admin_header()
    )

    assert response.status_code == 200
    assert response.json()["data"]["name"] == "NuevoGrupo"


def test_add_user_to_group(client, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        local_ad_service, "add_user_to_group", lambda g, u: calls.append((g, u))
    )

    response = client.post(
        f"/api/local-ad/groups/Docentes/members/{uuid.uuid4()}", headers=_admin_header()
    )

    assert response.status_code == 200
    assert len(calls) == 1


def test_endpoints_require_admin_role(client) -> None:
    token = create_user_token(str(uuid.uuid4()), "empleado@uta.edu.ec", ["R_EMPLOYEE"])
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/local-ad/users", headers=headers)

    assert response.status_code == 403
