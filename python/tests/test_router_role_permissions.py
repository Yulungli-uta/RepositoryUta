from uuid import uuid4

from repositoryuta.core.security.jwt import create_user_token
from repositoryuta.models.rbac import Permission, Role, RolePermission


def _admin_header() -> dict[str, str]:
    token = create_user_token(str(uuid4()), "admin@uta.edu.ec", ["Administrador"])
    return {"Authorization": f"Bearer {token}"}


def test_get_effective_permissions_is_public_and_cached(client, sqlite_session) -> None:
    role = Role(name="R_RH", is_active=True)
    permission = Permission(name="Ver", module="Empleados", action="Read")
    sqlite_session.add_all([role, permission])
    sqlite_session.flush()
    sqlite_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    sqlite_session.flush()

    response = client.get("/api/role-permissions/effective", params={"roles": ["R_RH"]})

    assert response.status_code == 200
    # Ambas formas: "MODULO.ACCION" (historica) y el name real del permiso.
    assert sorted(response.json()["data"]) == ["EMPLEADOS.READ", "VER"]
    assert response.headers["cache-control"] == "public, max-age=60"


def test_get_effective_permissions_distinguishes_same_module_action(
    client, sqlite_session
) -> None:
    """Caso DINARDAP: varios permisos comparten module+action a proposito (para no
    ampliar el CHECK de acciones) y solo se distinguen por name. Sin el name en la
    respuesta, todos colapsaban en un unico "MODULO.ACCION" y ningun consumidor podia
    pedir el permiso fino de uno en particular."""
    role = Role(name="R_DINARDAP_LEGACY", is_active=True)
    permissions = [
        Permission(name="DINARDAP.REGISTRO_CIVIL.READ", module="DINARDAP", action="READ"),
        Permission(name="DINARDAP.TCE.READ", module="DINARDAP", action="READ"),
        Permission(name="DINARDAP.TITULOS.READ", module="DINARDAP", action="READ"),
    ]
    sqlite_session.add_all([role, *permissions])
    sqlite_session.flush()
    sqlite_session.add_all(
        [RolePermission(role_id=role.id, permission_id=p.id) for p in permissions]
    )
    sqlite_session.flush()

    response = client.get(
        "/api/role-permissions/effective", params={"roles": ["R_DINARDAP_LEGACY"]}
    )

    assert response.status_code == 200
    assert sorted(response.json()["data"]) == [
        "DINARDAP.READ",
        "DINARDAP.REGISTRO_CIVIL.READ",
        "DINARDAP.TCE.READ",
        "DINARDAP.TITULOS.READ",
    ]


def test_get_effective_permissions_empty_roles_returns_empty(client) -> None:
    response = client.get("/api/role-permissions/effective")
    assert response.status_code == 200
    assert response.json()["data"] == []


def test_get_by_role_returns_all_without_pagination(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    permissions = [Permission(name=f"P{i}", module="M", action="Read") for i in range(3)]
    sqlite_session.add_all([role, *permissions])
    sqlite_session.flush()
    sqlite_session.add_all(
        [RolePermission(role_id=role.id, permission_id=p.id) for p in permissions]
    )
    sqlite_session.flush()

    response = client.get(f"/api/role-permissions/role/{role.id}", headers=_admin_header())

    assert response.status_code == 200
    assert len(response.json()["data"]) == 3


def test_list_response_is_not_wrapped_in_apiresponse(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    permission = Permission(name="Ver", module="M", action="Read")
    sqlite_session.add_all([role, permission])
    sqlite_session.flush()
    sqlite_session.add(RolePermission(role_id=role.id, permission_id=permission.id))
    sqlite_session.flush()

    response = client.get("/api/role-permissions", headers=_admin_header())

    assert response.status_code == 200
    body = response.json()
    assert "success" not in body
    assert body["totalCount"] == 1


def test_create_and_delete_role_permission(client, sqlite_session) -> None:
    role = Role(name="R_RH")
    permission = Permission(name="Ver", module="M", action="Read")
    sqlite_session.add_all([role, permission])
    sqlite_session.flush()

    created = client.post(
        "/api/role-permissions",
        json={"roleId": role.id, "permissionId": permission.id},
        headers=_admin_header(),
    )
    assert created.status_code == 200

    deleted = client.delete(
        f"/api/role-permissions/{role.id}/{permission.id}", headers=_admin_header()
    )
    assert deleted.status_code == 200

    missing = client.get(
        f"/api/role-permissions/{role.id}/{permission.id}", headers=_admin_header()
    )
    assert missing.status_code == 404
