import logging
import ssl
import uuid
from dataclasses import dataclass, replace

from ldap3 import (
    BASE,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    NTLM,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    Tls,
)
from ldap3.core.exceptions import LDAPEntryAlreadyExistsResult

from repositoryuta.config import LocalAdSettings, get_settings
from repositoryuta.core.exceptions import BusinessValidationError, ConflictError, NotFoundError

logger = logging.getLogger(__name__)

# Espejo de LocalAdDirectoryService.cs (CRUD de usuarios y grupos en AD local
# via LDAP) + LocalAdIdentityProvider.cs (bind-as-user). Usa la cuenta de
# servicio configurada en LocalAdSettings para todas las operaciones,
# excepto authenticate_user (que hace bind con las credenciales del propio
# usuario final).

_USER_ATTRIBUTES = [
    "objectGUID",
    "displayName",
    "mail",
    "userPrincipalName",
    "sAMAccountName",
    "givenName",
    "sn",
    "department",
    "title",
    "userAccountControl",
]

_GROUP_ATTRIBUTES = ["objectGUID", "cn", "description", "mail"]

_MAX_CN_ATTEMPTS = 10


@dataclass
class DirectoryUser:
    """Espejo del record DirectoryUser (Infrastructure/Identity/Contracts)."""

    id: str
    email: str
    display_name: str
    given_name: str | None
    surname: str | None
    job_title: str | None
    department: str | None
    is_enabled: bool
    cn_warning: str | None = None
    id_card: str | None = None


@dataclass
class DirectoryGroup:
    """Espejo del record DirectoryGroup."""

    id: str
    name: str
    description: str | None
    email: str | None


@dataclass
class AuthResult:
    """Espejo de ProviderAuthResult."""

    success: bool
    email: str | None
    display_name: str | None
    failure_reason: str | None = None


def _escape_ldap(value: str) -> str:
    return (
        value.replace("\\", "\\5c")
        .replace("*", "\\2a")
        .replace("(", "\\28")
        .replace(")", "\\29")
        .replace("\x00", "\\00")
    )


def _escape_guid_filter(guid_str: str) -> str:
    """Convierte un GUID string al formato octet-escaped de un filtro LDAP,
    usando el mismo layout de bytes que .NET's Guid.ToByteArray() (mixed-
    endian) — `uuid.UUID.bytes_le` produce exactamente esa misma secuencia."""
    try:
        guid = uuid.UUID(guid_str)
    except ValueError:
        return _escape_ldap(guid_str)
    return "".join(f"\\{b:02x}" for b in guid.bytes_le)


def _is_guid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False


def _bind_credentials(opts: LocalAdSettings) -> tuple[str, str, str]:
    """Espejo de BuildServiceConnection: detecta el formato de la cuenta de
    servicio para elegir el tipo de autenticacion (Simple vs NTLM)."""
    account_dn = opts.service_account_dn or ""

    if "=" in account_dn or "@" in account_dn:
        return account_dn, SIMPLE, ""
    if "\\" in account_dn:
        return account_dn, NTLM, ""

    domain = ".".join(
        part.strip()[3:]
        for part in (opts.base_dn or "").split(",")
        if part.strip().upper().startswith("DC=")
    )
    bind_user = f"{account_dn}@{domain}" if domain else account_dn
    return bind_user, SIMPLE, domain


def _build_connection() -> Connection:
    """Espejo de BuildServiceConnection: bind con la cuenta de servicio, canal
    LDAP simple (puerto 389 por defecto)."""
    opts = get_settings().local_ad
    bind_user, auth_type, _domain = _bind_credentials(opts)

    server = Server(opts.server, port=opts.port, get_info=None)
    connection = Connection(
        server,
        user=bind_user,
        password=opts.service_account_password,
        authentication=auth_type,
        receive_timeout=opts.timeout_seconds,
        raise_exceptions=True,
    )
    connection.bind()
    return connection


def _build_password_connection() -> Connection:
    """Espejo de BuildPasswordConnection: canal LDAPS (SSL obligatorio) usado
    exclusivamente para operaciones de contraseña (unicodePwd) — AD rechaza
    esa escritura en un canal sin cifrar."""
    opts = get_settings().local_ad
    bind_user, auth_type, _domain = _bind_credentials(opts)

    # Acepta certificados autofirmados del DC interno, igual que
    # VerifyServerCertificate = (_, _) => true en el .NET real.
    tls = Tls(validate=ssl.CERT_NONE)
    server = Server(opts.server, port=opts.ldaps_port, use_ssl=True, tls=tls, get_info=None)
    connection = Connection(
        server,
        user=bind_user,
        password=opts.service_account_password,
        authentication=auth_type,
        receive_timeout=opts.timeout_seconds,
        raise_exceptions=True,
    )
    connection.bind()
    return connection


def _real_entries(connection: Connection) -> list[dict]:
    """Filtra connection.response a solo entradas reales (type=='searchResEntry'),
    descartando referencias LDAP (searchResRef) que el servidor devuelve cuando
    la busqueda cruza un limite de particion/dominio del AD — sin esto, una
    referencia (sin dn ni atributos) se mapea como un grupo/usuario vacio.
    System.DirectoryServices.Protocols (.NET) ya hace este filtro
    automaticamente dentro de SearchResponse.Entries."""
    return [entry for entry in connection.response if entry.get("type") == "searchResEntry"]


def _raw_attr(entry: dict, name: str) -> bytes | None:
    values = entry.get("raw_attributes", {}).get(name) or []
    return values[0] if values else None


def _attr(entry: dict, name: str) -> str:
    values = entry.get("attributes", {}).get(name)
    if not values:
        return ""
    value = values[0] if isinstance(values, list) else values
    return str(value) if value is not None else ""


def _object_id(entry: dict) -> str:
    guid_bytes = _raw_attr(entry, "objectGUID")
    return str(uuid.UUID(bytes_le=guid_bytes)) if guid_bytes else entry.get("dn", "")


def _map_user(entry: dict) -> DirectoryUser:
    mail = _attr(entry, "mail")
    upn = _attr(entry, "userPrincipalName")
    uac = _attr(entry, "userAccountControl")

    return DirectoryUser(
        id=_object_id(entry),
        email=mail or upn,
        display_name=_attr(entry, "displayName"),
        given_name=_attr(entry, "givenName") or None,
        surname=_attr(entry, "sn") or None,
        job_title=_attr(entry, "title") or None,
        department=_attr(entry, "department") or None,
        is_enabled=not uac.startswith("514"),
    )


def _map_group(entry: dict) -> DirectoryGroup:
    return DirectoryGroup(
        id=_object_id(entry),
        name=_attr(entry, "cn"),
        description=_attr(entry, "description") or None,
        email=_attr(entry, "mail") or None,
    )


def _search_single_user(
    connection: Connection, base_dn: str, ldap_filter: str
) -> DirectoryUser | None:
    connection.search(base_dn, ldap_filter, SUBTREE, attributes=_USER_ATTRIBUTES)
    entries = _real_entries(connection)
    return _map_user(entries[0]) if entries else None


def _search_single_group(
    connection: Connection, base_dn: str, ldap_filter: str
) -> DirectoryGroup | None:
    connection.search(base_dn, ldap_filter, SUBTREE, attributes=_GROUP_ATTRIBUTES)
    entries = _real_entries(connection)
    return _map_group(entries[0]) if entries else None


def _get_dn_by_id(connection: Connection, object_id: str, base_dn: str) -> str | None:
    """Espejo de GetDnById: por objectGUID si es un GUID valido, si no por
    UPN/mail/sAMAccountName."""
    if _is_guid(object_id):
        ldap_filter = f"(objectGUID={_escape_guid_filter(object_id)})"
        connection.search(base_dn, ldap_filter, SUBTREE, attributes=["distinguishedName"])
        entries = _real_entries(connection)
        if entries:
            return entries[0]["dn"]

    esc = _escape_ldap(object_id)
    ldap_filter = (
        f"(&(objectClass=user)(|(userPrincipalName={esc})(mail={esc})(sAMAccountName={esc})))"
    )
    connection.search(base_dn, ldap_filter, SUBTREE, attributes=["distinguishedName"])
    entries = _real_entries(connection)
    return entries[0]["dn"] if entries else None


def _resolve_group_dn(connection: Connection, base_dn: str, cn_or_id: str) -> str | None:
    """Espejo de ResolveGroupDn: por objectGUID si es un GUID valido, si no
    por CN (nombre legible)."""
    if _is_guid(cn_or_id):
        ldap_filter = f"(&(objectClass=group)(objectGUID={_escape_guid_filter(cn_or_id)}))"
        connection.search(base_dn, ldap_filter, SUBTREE, attributes=["distinguishedName"])
        entries = _real_entries(connection)
        return entries[0]["dn"] if entries else None

    ldap_filter = f"(&(objectClass=group)(cn={_escape_ldap(cn_or_id)}))"
    connection.search(base_dn, ldap_filter, SUBTREE, attributes=["distinguishedName"])
    entries = _real_entries(connection)
    return entries[0]["dn"] if entries else None


# ── Autenticacion ─────────────────────────────────────────────────────────────


def authenticate_user(username: str, password: str) -> AuthResult:
    """Espejo de LocalAdIdentityProvider.AuthenticateAsync: el bind mismo
    prueba las credenciales, no se compara contra nada guardado."""
    opts = get_settings().local_ad
    if "@" in username:
        bind_dn = username
    elif opts.netbios_domain:
        bind_dn = f"{opts.netbios_domain}\\{username}"
    else:
        bind_dn = username

    server = Server(opts.server, port=opts.port, get_info=None)
    connection = None
    try:
        connection = Connection(
            server,
            user=bind_dn,
            password=password,
            authentication=SIMPLE,
            receive_timeout=opts.timeout_seconds,
            raise_exceptions=True,
        )
        connection.bind()

        esc = _escape_ldap(username)
        ldap_filter = (
            f"(&(objectClass=user)(|(sAMAccountName={esc})(userPrincipalName={esc})(mail={esc})))"
        )
        connection.search(
            opts.base_dn,
            ldap_filter,
            SUBTREE,
            attributes=["displayName", "mail", "userPrincipalName"],
        )
        entries = _real_entries(connection)
        entry = entries[0] if entries else None
        display_name = (entry and _attr(entry, "displayName")) or username
        email = (entry and (_attr(entry, "mail") or _attr(entry, "userPrincipalName"))) or username

        logger.info("AD local autenticó usuario %s", username)
        return AuthResult(success=True, email=email, display_name=display_name)
    except Exception as exc:
        error_code = getattr(exc, "result", None)
        if error_code == 49 or "invalidCredentials" in str(exc):
            logger.warning("AD local rechazó credenciales para %s", username)
            return AuthResult(
                success=False, email=None, display_name=None, failure_reason="Invalid credentials"
            )
        logger.error("Error conectando a AD local para %s: %s", username, exc)
        return AuthResult(
            success=False, email=None, display_name=None, failure_reason="Directory unavailable"
        )
    finally:
        if connection is not None:
            connection.unbind()


# ── Usuarios ──────────────────────────────────────────────────────────────────


def find_user_by_email(email: str) -> DirectoryUser | None:
    """Espejo de LocalAdDirectoryService.GetUserByEmailAsync."""
    opts = get_settings().local_ad
    esc = _escape_ldap(email)
    ldap_filter = f"(&(objectClass=user)(|(userPrincipalName={esc})(mail={esc})))"

    connection = _build_connection()
    try:
        return _search_single_user(connection, opts.base_dn, ldap_filter)
    finally:
        connection.unbind()


def get_user(object_id: str) -> DirectoryUser | None:
    """Espejo de LocalAdDirectoryService.GetUserAsync."""
    opts = get_settings().local_ad
    ldap_filter = f"(objectGUID={_escape_guid_filter(object_id)})"

    connection = _build_connection()
    try:
        return _search_single_user(connection, opts.base_dn, ldap_filter)
    finally:
        connection.unbind()


def get_user_groups(user_id: str) -> list[DirectoryGroup]:
    """Espejo de LocalAdDirectoryService.GetUserGroupsAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        user_dn = _get_dn_by_id(connection, user_id, opts.base_dn)
        if user_dn is None:
            return []

        escaped_dn = _escape_ldap(user_dn)
        ldap_filter = f"(&(objectClass=group)(member={escaped_dn}))"
        connection.search(opts.base_dn, ldap_filter, SUBTREE, attributes=_GROUP_ATTRIBUTES)
        return [_map_group(entry) for entry in _real_entries(connection)]
    finally:
        connection.unbind()


def list_users(
    page: int = 1, page_size: int = 50, name_filter: str | None = None
) -> list[DirectoryUser]:
    """Espejo de LocalAdDirectoryService.ListUsersAsync."""
    opts = get_settings().local_ad
    if name_filter:
        esc = _escape_ldap(name_filter)
        ldap_filter = (
            f"(&(objectClass=user)(objectCategory=person)"
            f"(|(cn=*{esc}*)(mail=*{esc}*)(sAMAccountName=*{esc}*)))"
        )
    else:
        ldap_filter = "(&(objectClass=user)(objectCategory=person))"

    connection = _build_connection()
    try:
        connection.search(opts.base_dn, ldap_filter, SUBTREE, attributes=_USER_ATTRIBUTES)
        entries = _real_entries(connection)
        page_entries = entries[(page - 1) * page_size : (page - 1) * page_size + page_size]
        return [_map_user(entry) for entry in page_entries]
    finally:
        connection.unbind()


def create_user(
    user: DirectoryUser,
    initial_password: str,
    target_ou: str,
    force_password_change: bool = True,
) -> DirectoryUser:
    """Espejo de LocalAdDirectoryService.CreateUserAsync: bucle de CN unico
    con sufijo numerico, luego set de password via LDAPS (unicodePwd) y
    habilitacion de la cuenta."""
    if not target_ou or not target_ou.strip():
        raise BusinessValidationError(
            "targetOu no puede estar vacío al crear usuario en AD Local. "
            "Verifique LocalAd:FuncionariosActivosOu o LocalAd:EstudiantesActivosOu."
        )

    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        upn = user.email if "@" in user.email else f"{user.email}@{opts.netbios_domain}"
        sam = upn.split("@")[0][:20]

        existing = _search_single_user(
            connection,
            opts.base_dn,
            f"(&(objectClass=user)(|(userPrincipalName={_escape_ldap(upn)})"
            f"(mail={_escape_ldap(user.email)})))",
        )
        if existing is not None:
            raise ConflictError(
                f"Ya existe un usuario en AD Local con UPN '{upn}' o email '{user.email}' "
                f"(objectGUID={existing.id})."
            )

        base_cn = user.display_name.strip().replace(",", "\\,")
        cn_warning: str | None = None

        for attempt in range(_MAX_CN_ATTEMPTS + 1):
            used_cn = base_cn if attempt == 0 else f"{base_cn} {attempt}"
            used_dn = f"CN={used_cn},{target_ou}"

            attributes = {
                "objectClass": "user",
                "cn": used_cn,
                "displayName": user.display_name,
                "userPrincipalName": upn,
                "sAMAccountName": sam,
                "mail": user.email,
                # 514 = NORMAL_ACCOUNT | ACCOUNTDISABLE — se habilita tras setear contraseña.
                "userAccountControl": "514",
            }
            if user.given_name:
                attributes["givenName"] = user.given_name
            if user.surname:
                attributes["sn"] = user.surname
            if user.department:
                attributes["department"] = user.department
            if user.job_title:
                attributes["title"] = user.job_title
            if user.id_card:
                attributes["employeeID"] = user.id_card

            try:
                connection.add(used_dn, attributes=attributes)
            except LDAPEntryAlreadyExistsResult:
                logger.warning(
                    "[AD-CREATE] CN '%s' ya existe en AD (intento %s/%s). Reintentando. UPN=%s",
                    used_cn, attempt, _MAX_CN_ATTEMPTS, upn,
                )
                continue

            if attempt > 0:
                cn_warning = (
                    f"CN '{base_cn}' ya existía en AD Local ({attempt} intento(s)). "
                    f"Se usó CN '{used_cn}' para evitar conflicto."
                )
                logger.warning(
                    "[AD-CREATE] CN ajustado automaticamente. original=%s usado=%s UPN=%s",
                    base_cn, used_cn, upn,
                )

            _set_password_internal(used_dn, initial_password)
            connection.modify(used_dn, {"userAccountControl": [(MODIFY_REPLACE, ["512"])]})
            if force_password_change:
                connection.modify(used_dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0"])]})

            logger.info("[AD-CREATE] Usuario creado. DN=%s UPN=%s OU=%s", used_dn, upn, target_ou)
            created = _search_single_user(
                connection, opts.base_dn, f"(userPrincipalName={_escape_ldap(upn)})"
            )
            if created is None:
                raise NotFoundError(f"Usuario creado pero no encontrado por UPN '{upn}'.")
            return replace(created, cn_warning=cn_warning)

        raise ConflictError(
            f"No se pudo crear el usuario '{upn}' en AD Local: los {_MAX_CN_ATTEMPTS} "
            f"candidatos de CN basados en '{base_cn}' ya están ocupados."
        )
    finally:
        connection.unbind()


def update_user(object_id: str, updated: DirectoryUser) -> DirectoryUser:
    """Espejo de LocalAdDirectoryService.UpdateUserAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        dn = _get_dn_by_id(connection, object_id, opts.base_dn)
        if dn is None:
            raise NotFoundError(f"Usuario no encontrado en AD: {object_id}")

        changes: dict[str, list] = {"displayName": [(MODIFY_REPLACE, [updated.display_name])]}
        if updated.given_name:
            changes["givenName"] = [(MODIFY_REPLACE, [updated.given_name])]
        if updated.surname:
            changes["sn"] = [(MODIFY_REPLACE, [updated.surname])]
        if updated.job_title:
            changes["title"] = [(MODIFY_REPLACE, [updated.job_title])]
        if updated.department:
            changes["department"] = [(MODIFY_REPLACE, [updated.department])]

        connection.modify(dn, changes)
        logger.info("AD local: usuario actualizado %s", object_id)

        result = _search_single_user(
            connection, opts.base_dn, f"(objectGUID={_escape_guid_filter(object_id)})"
        )
        if result is None:
            raise NotFoundError(f"Usuario no encontrado en AD: {object_id}")
        return result
    finally:
        connection.unbind()


def set_user_enabled(object_id: str, enabled: bool) -> None:
    """Espejo de LocalAdDirectoryService.SetUserEnabledAsync. 512=habilitado,
    514=deshabilitado (512 | 2)."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        dn = _get_dn_by_id(connection, object_id, opts.base_dn)
        if dn is None:
            raise NotFoundError(f"Usuario no encontrado en AD: {object_id}")

        uac = "512" if enabled else "514"
        connection.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [uac])]})
        action = "habilitado" if enabled else "deshabilitado"
        logger.info("AD local: usuario %s %s", object_id, action)
    finally:
        connection.unbind()


def delete_user(object_id: str) -> None:
    """Espejo de LocalAdDirectoryService.DeleteUserAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        dn = _get_dn_by_id(connection, object_id, opts.base_dn)
        if dn is None:
            raise NotFoundError(f"Usuario no encontrado en AD: {object_id}")

        connection.delete(dn)
        logger.info("AD local: usuario eliminado %s", object_id)
    finally:
        connection.unbind()


def move_user_to_ou(user_object_id: str, target_ou_dn: str) -> None:
    """Espejo de LocalAdDirectoryService.MoveUserToOuAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        current_dn = _get_dn_by_id(connection, user_object_id, opts.base_dn)
        if current_dn is None:
            raise NotFoundError(f"Usuario no encontrado en AD para mover OU: {user_object_id}")

        rdn = current_dn.split(",")[0]
        connection.modify_dn(current_dn, rdn, new_superior=target_ou_dn)
        logger.info("[AD-MOVE] Usuario %s movido a %s", user_object_id, target_ou_dn)
    finally:
        connection.unbind()


def _set_password_internal(dn: str, password: str) -> None:
    """Espejo de SetPasswordInternal: establece unicodePwd via una conexion
    LDAPS independiente (SSL obligatorio) — AD rechaza esta escritura en un
    canal sin cifrar. Usa la extension nativa de ldap3 para AD en vez del
    encoding manual del .NET (Unicode + comillas), equivalente pero mas
    simple y menos propenso a error."""
    connection = _build_password_connection()
    try:
        connection.extend.microsoft.modify_password(dn, password)
    finally:
        connection.unbind()


def change_user_password(
    user_id: str, new_password: str, force_password_change: bool = True
) -> None:
    """Espejo de LocalAdDirectoryService.ChangeUserPasswordAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        dn = _get_dn_by_id(connection, user_id, opts.base_dn)
        if dn is None:
            raise NotFoundError(f"Usuario no encontrado en AD: {user_id}")
    finally:
        connection.unbind()

    _set_password_internal(dn, new_password)

    if force_password_change:
        connection2 = _build_connection()
        try:
            connection2.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, ["0"])]})
        finally:
            connection2.unbind()

    logger.info("AD local: contraseña restablecida para %s", user_id)


# ── Grupos ────────────────────────────────────────────────────────────────────


def get_group(object_id: str) -> DirectoryGroup | None:
    """Espejo de LocalAdDirectoryService.GetGroupAsync."""
    opts = get_settings().local_ad
    ldap_filter = f"(objectGUID={_escape_guid_filter(object_id)})"

    connection = _build_connection()
    try:
        return _search_single_group(connection, opts.base_dn, ldap_filter)
    finally:
        connection.unbind()


def list_groups(
    page: int = 1, page_size: int = 50, name_filter: str | None = None
) -> list[DirectoryGroup]:
    """Espejo de LocalAdDirectoryService.ListGroupsAsync."""
    opts = get_settings().local_ad
    if name_filter:
        ldap_filter = f"(&(objectClass=group)(cn=*{_escape_ldap(name_filter)}*))"
    else:
        ldap_filter = "(objectClass=group)"

    connection = _build_connection()
    try:
        connection.search(opts.base_dn, ldap_filter, SUBTREE, attributes=_GROUP_ATTRIBUTES)
        entries = _real_entries(connection)
        page_entries = entries[(page - 1) * page_size : (page - 1) * page_size + page_size]
        return [_map_group(entry) for entry in page_entries]
    finally:
        connection.unbind()


def create_group(group_name: str, description: str | None = None) -> DirectoryGroup:
    """Espejo de LocalAdDirectoryService.CreateGroupAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        cn = group_name.replace(",", "\\,")
        dn = f"CN={cn},{opts.groups_ou}"
        sam = cn[:20]

        attributes = {
            "objectClass": "group",
            "cn": cn,
            "sAMAccountName": sam,
            # -2147483646 = Global Security Group.
            "groupType": "-2147483646",
        }
        if description:
            attributes["description"] = description

        connection.add(dn, attributes=attributes)
        logger.info("AD local: grupo creado %s", dn)

        created = _search_single_group(connection, opts.base_dn, f"(cn={_escape_ldap(cn)})")
        if created is None:
            raise NotFoundError(f"Grupo creado pero no encontrado: {cn}")
        return created
    finally:
        connection.unbind()


def add_user_to_group(group_id: str, user_id: str) -> None:
    """Espejo de LocalAdDirectoryService.AddUserToGroupAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        group_dn = _resolve_group_dn(connection, opts.base_dn, group_id)
        if group_dn is None:
            raise NotFoundError(f"Grupo no encontrado: {group_id}")
        user_dn = _get_dn_by_id(connection, user_id, opts.base_dn)
        if user_dn is None:
            raise NotFoundError(f"Usuario no encontrado: {user_id}")

        connection.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
        logger.info("AD local: usuario %s agregado al grupo %s", user_id, group_id)
    finally:
        connection.unbind()


def remove_user_from_group(group_id: str, user_id: str) -> None:
    """Espejo de LocalAdDirectoryService.RemoveUserFromGroupAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        group_dn = _resolve_group_dn(connection, opts.base_dn, group_id)
        if group_dn is None:
            raise NotFoundError(f"Grupo no encontrado: {group_id}")
        user_dn = _get_dn_by_id(connection, user_id, opts.base_dn)
        if user_dn is None:
            raise NotFoundError(f"Usuario no encontrado: {user_id}")

        connection.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
        logger.info("AD local: usuario %s removido del grupo %s", user_id, group_id)
    finally:
        connection.unbind()


def is_user_in_group(group_id: str, user_id: str) -> bool:
    """Espejo de LocalAdDirectoryService.IsUserInGroupAsync."""
    opts = get_settings().local_ad
    connection = _build_connection()
    try:
        group_dn = _resolve_group_dn(connection, opts.base_dn, group_id)
        if group_dn is None:
            return False
        user_dn = _get_dn_by_id(connection, user_id, opts.base_dn)
        if user_dn is None:
            return False

        connection.search(group_dn, "(objectClass=group)", BASE, attributes=["member"])
        entries = _real_entries(connection)
        if not entries:
            return False

        members = entries[0].get("attributes", {}).get("member") or []
        return any(str(m).lower() == user_dn.lower() for m in members)
    finally:
        connection.unbind()
