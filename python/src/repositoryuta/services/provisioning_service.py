import logging
import secrets
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.core.exceptions import ConflictError
from repositoryuta.core.pagination import PagedResult
from repositoryuta.models.identity import (
    PROVISIONING_STATUS_NAMES,
    ProvisioningStatus,
    User,
    UserEmployee,
    UserProvisioning,
)
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.schemas.provisioning import (
    BulkProvisioningResultRead,
    CompletePendingResultRead,
    DisableEmployeeResultRead,
    PasswordResetResultRead,
    ProvisionEmployeeRequest,
    UserProvisioningRead,
)
from repositoryuta.services import azure_management_service as azure_mgmt
from repositoryuta.services import institutional_email_service, license_service, local_ad_service
from repositoryuta.services.azure_management_service import EntraSyncStatus
from repositoryuta.services.local_ad_service import DirectoryUser

logger = logging.getLogger(__name__)

# Espejo de EmployeeProvisioningService.cs.
#
# Nota de fidelidad sobre atomicidad: el .NET envuelve los pasos 2-7 de
# DoProvisionAsync en una transaccion SQL explicita, pero esa transaccion NUNCA
# puede cubrir el efecto de las llamadas a AD Local/Graph (no son parte de la
# misma transaccion distribuida) — si AD Local ya creo la cuenta y un paso SQL
# posterior falla, el registro queda igual marcado LocalAdFailed y la cuenta AD
# queda huerfana (no reflejada en LocalAdObjectId). Aqui se replica el mismo
# efecto observable con rollback() + un commit posterior solo para el estado de
# error, sin necesidad de un SAVEPOINT: mismo comportamiento, misma limitacion.

_COMPLETABLE_STATUSES = {
    int(ProvisioningStatus.PENDING_ENTRA_SYNC),
    int(ProvisioningStatus.SYNCED_IN_ENTRA),
    int(ProvisioningStatus.LICENSE_FAILED),
}


def _status_name(status: ProvisioningStatus) -> str:
    return PROVISIONING_STATUS_NAMES[status]


def _update_status(
    session: Session, record: UserProvisioning, status: ProvisioningStatus, message: str | None
) -> None:
    record.provisioning_status_id = int(status)
    record.provisioning_status_name = _status_name(status)
    record.error_message = message
    record.updated_at = datetime.now()
    record.last_checked_at = datetime.now()
    session.commit()


def _map_to_dto(record: UserProvisioning) -> UserProvisioningRead:
    """Separa avisos ([AVISO] ...) de errores reales — mismo criterio que
    MapToDto en .NET, para que el frontend distinga "algo salio mal" de
    "completado con advertencia"."""
    error_message = record.error_message
    warning: str | None = None

    if error_message and error_message.upper().startswith("[AVISO]"):
        warning = error_message[len("[AVISO]") :].strip()
        error_message = None

    return UserProvisioningRead(
        id=str(record.id),
        hr_employee_id=record.hr_employee_id,
        email=record.email,
        display_name=record.display_name,
        given_name=record.given_name,
        surname=record.surname,
        department_id=record.department_id,
        department_name=record.department_name,
        job_title=record.job_title,
        employee_type_id=record.employee_type_id,
        employee_type_name=record.employee_type_name,
        provisioning_status_id=record.provisioning_status_id,
        provisioning_status_name=record.provisioning_status_name,
        auth_user_id=str(record.auth_user_id) if record.auth_user_id else None,
        local_ad_object_id=record.local_ad_object_id,
        entra_object_id=record.entra_object_id,
        license_sku_id=record.license_sku_id,
        provisioned_at=record.provisioned_at,
        license_assigned_at=record.license_assigned_at,
        last_checked_at=record.last_checked_at,
        error_message=error_message,
        requested_by=record.requested_by,
        source_reference=record.source_reference,
        created_at=record.created_at,
        updated_at=record.updated_at,
        warning=warning,
    )


def _create_initial_record(req: ProvisionEmployeeRequest) -> UserProvisioning:
    return UserProvisioning(
        id=uuid4(),
        hr_employee_id=req.hr_employee_id,
        email=req.email or "",
        display_name=req.display_name,
        given_name=req.given_name,
        surname=req.surname,
        department_id=req.department_id,
        department_name=req.department_name,
        job_title=req.job_title,
        employee_type_id=req.employee_type_id,
        employee_type_name=req.employee_type_name,
        provisioning_status_id=int(ProvisioningStatus.REQUESTED),
        provisioning_status_name=_status_name(ProvisioningStatus.REQUESTED),
        source_reference=req.source_reference,
    )


# ── Aprovisionamiento individual ─────────────────────────────────────────────


def provision(session: Session, req: ProvisionEmployeeRequest) -> UserProvisioningRead:
    logger.info(
        "[PROVISIONING] Iniciando aprovisionamiento. HrEmployeeId=%s | GivenName=%s | "
        "Surname=%s | PersonalEmail=%s",
        req.hr_employee_id, req.given_name, req.surname,
        req.personal_email or "(no proporcionado)",
    )

    ad_settings = get_settings().local_ad
    institutional_email = institutional_email_service.generate_available_email(
        session, req.hr_employee_id, req.given_name, req.surname, ad_settings.base_dn
    )
    logger.info(
        "[PROVISIONING] Email institucional generado: %s para HrEmployeeId=%s",
        institutional_email, req.hr_employee_id,
    )
    req = req.model_copy(update={"email": institutional_email})

    existing = (
        session.query(UserProvisioning)
        .filter(
            (UserProvisioning.hr_employee_id == req.hr_employee_id)
            | (UserProvisioning.email == req.email),
            UserProvisioning.provisioning_status_id != int(ProvisioningStatus.LOCAL_AD_FAILED),
            UserProvisioning.provisioning_status_id != int(ProvisioningStatus.LICENSE_FAILED),
        )
        .order_by(UserProvisioning.created_at.desc())
        .first()
    )
    if existing is not None:
        logger.info(
            "[PROVISIONING] Duplicado detectado. Empleado %s (%s) ya tiene aprovisionamiento "
            "activo id=%s en estado %s",
            req.hr_employee_id, existing.email, existing.id, existing.provisioning_status_name,
        )
        raise ConflictError(
            f"El empleado {existing.hr_employee_id} ya tiene una cuenta activa: "
            f"{existing.email} (estado: {existing.provisioning_status_name})"
        )

    record = _create_initial_record(req)
    session.add(record)
    session.commit()

    logger.info(
        "[PROVISIONING] Registro guardado. ProvisioningId=%s | Email=%s — Iniciando "
        "creación en AD...",
        record.id, record.email,
    )

    _do_provision(session, record, req)

    logger.info(
        "[PROVISIONING] Resultado final. ProvisioningId=%s | Status=%s | Error=%s",
        record.id, record.provisioning_status_name, record.error_message or "ninguno",
    )
    return _map_to_dto(record)


def provision_bulk(
    session: Session, requests: list[ProvisionEmployeeRequest]
) -> list[BulkProvisioningResultRead]:
    """Espejo de ProvisionBulkAsync. El .NET usa hasta 5 tareas concurrentes con
    SemaphoreSlim; aqui se procesa secuencialmente (misma simplificacion ya
    aplicada a las operaciones bulk de azure_management_service.py — una
    Session de SQLAlchemy no es segura para usar desde varios hilos a la vez)."""
    results: list[BulkProvisioningResultRead] = []
    for req in requests:
        try:
            dto = provision(session, req)
            results.append(
                BulkProvisioningResultRead(
                    hr_employee_id=req.hr_employee_id, email=dto.email, success=True,
                    provisioning=dto, error=None,
                )
            )
        except Exception as exc:
            logger.error("Error en bulk provisioning para empleado %s: %s", req.hr_employee_id, exc)
            results.append(
                BulkProvisioningResultRead(
                    hr_employee_id=req.hr_employee_id, email=req.email or "", success=False,
                    provisioning=None, error=str(exc),
                )
            )
    return results


# ── Consulta / listado ────────────────────────────────────────────────────────


def get_status(session: Session, provisioning_id: UUID) -> UserProvisioningRead | None:
    record = session.get(UserProvisioning, provisioning_id)
    return _map_to_dto(record) if record is not None else None


def list_provisioning(
    session: Session, page: int, page_size: int, status_id: int | None = None
) -> PagedResult[UserProvisioningRead]:
    query = session.query(UserProvisioning)
    if status_id is not None:
        query = query.filter(UserProvisioning.provisioning_status_id == status_id)

    total = query.count()
    items = (
        query.order_by(UserProvisioning.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PagedResult(
        items=[_map_to_dto(item) for item in items], page=page, page_size=page_size,
        total_count=total,
    )


# ── Reintento ─────────────────────────────────────────────────────────────────


def retry(
    session: Session, provisioning_id: UUID, new_initial_password: str | None = None
) -> UserProvisioningRead | None:
    record = session.get(UserProvisioning, provisioning_id)
    if record is None:
        return None

    if record.provisioning_status_id == int(ProvisioningStatus.LICENSE_FAILED):
        logger.info(
            "Aprovisionamiento %s: LicenseFailed — reintentando solo asignación de licencia.",
            provisioning_id,
        )
        return check_and_complete_provisioning(session, provisioning_id)

    if record.provisioning_status_id != int(ProvisioningStatus.LOCAL_AD_FAILED):
        logger.warning(
            "Aprovisionamiento %s no está en estado retryable (status=%s)",
            provisioning_id, record.provisioning_status_id,
        )
        return _map_to_dto(record)

    if not new_initial_password or not new_initial_password.strip():
        raise ValueError(
            "Se debe proporcionar una nueva contraseña inicial para reintentar la creación "
            "de cuenta en AD Local."
        )

    req = ProvisionEmployeeRequest(
        hr_employee_id=record.hr_employee_id,
        display_name=record.display_name,
        given_name=record.given_name or "",
        surname=record.surname or "",
        initial_password=new_initial_password,
        employee_type_id=record.employee_type_id,
        employee_type_name=record.employee_type_name,
        department_id=record.department_id,
        department_name=record.department_name,
        job_title=record.job_title,
        source_reference=record.source_reference,
        email=record.email,
    )

    record.provisioning_status_id = int(ProvisioningStatus.REQUESTED)
    record.provisioning_status_name = _status_name(ProvisioningStatus.REQUESTED)
    record.error_message = None
    record.updated_at = datetime.now()
    session.commit()

    _do_provision(session, record, req)
    return _map_to_dto(record)


# ── Lógica interna ────────────────────────────────────────────────────────────


def _do_provision(
    session: Session, record: UserProvisioning, req: ProvisionEmployeeRequest
) -> None:
    ad_settings = get_settings().local_ad
    try:
        domain = institutional_email_service.get_expected_domain(ad_settings.base_dn)
        email = req.email
        if not email:
            raise ValueError("No se generó correo institucional.")

        if domain and not email.lower().endswith(f"@{domain}"):
            raise ValueError(f"El correo debe usar el dominio institucional @{domain}")

        target_ou = ad_settings.funcionarios_activos_ou
        if not target_ou or not target_ou.strip():
            raise ValueError(
                "LocalAd:FuncionariosActivosOu no está configurado en appsettings.json."
            )

        dir_user = DirectoryUser(
            id="", email=email, display_name=req.display_name, given_name=req.given_name,
            surname=req.surname, job_title=req.job_title, department=req.department_name,
            is_enabled=True, id_card=req.id_card,
        )

        try:
            created = local_ad_service.create_user(
                dir_user, req.initial_password, target_ou, req.force_password_change
            )
        except Exception as ad_ex:
            logger.error("Error creando usuario en AD Local: %s — %s", email, ad_ex)
            session.rollback()
            _update_status(session, record, ProvisioningStatus.LOCAL_AD_FAILED, str(ad_ex))
            return

        record.local_ad_object_id = created.id
        record.provisioned_at = datetime.now()

        if created.cn_warning:
            logger.warning(
                "[PROVISIONING] CN ajustado en AD Local. HrEmployeeId=%s | %s",
                req.hr_employee_id, created.cn_warning,
            )
            record.error_message = f"[AVISO] {created.cn_warning}"

        _update_status(
            session, record, ProvisioningStatus.CREATED_IN_LOCAL_AD, record.error_message
        )

        auth_user = _ensure_auth_user(session, email, req.display_name)
        record.auth_user_id = auth_user.id
        logger.info(
            "[PROVISIONING] auth.tbl_Users: UserId=%s | Email=%s | DisplayName='%s'",
            auth_user.id, email, req.display_name,
        )

        _ensure_user_employee(session, auth_user.id, email, req.hr_employee_id)
        logger.info(
            "[PROVISIONING] auth.tbl_UserEmployees: UserId=%s | HrEmployeeId=%s | EmployeeEmail=%s",
            auth_user.id, req.hr_employee_id, email,
        )

        _ensure_default_role(session, auth_user.id)
        _ensure_default_ad_group(created.id, email)

        session.commit()

        try:
            sync = azure_mgmt.check_user_entra_sync(email)
            if sync.status in (EntraSyncStatus.SYNCED, EntraSyncStatus.DISABLED):
                record.entra_object_id = sync.azure_object_id
                _update_status(session, record, ProvisioningStatus.SYNCED_IN_ENTRA, None)
            else:
                _update_status(
                    session, record, ProvisioningStatus.PENDING_ENTRA_SYNC, sync.message
                )
        except Exception as sync_ex:
            logger.warning("No se pudo verificar Entra sync para %s: %s", email, sync_ex)
            _update_status(
                session,
                record,
                ProvisioningStatus.PENDING_ENTRA_SYNC,
                "Verificación de Entra sync pendiente",
            )

        logger.info(
            "Aprovisionamiento completado para empleado %s (%s) — status: %s",
            req.hr_employee_id, email, record.provisioning_status_name,
        )
    except Exception as exc:
        session.rollback()
        logger.error(
            "Error inesperado en aprovisionamiento de empleado %s: %s",
            req.hr_employee_id, exc,
        )
        _update_status(session, record, ProvisioningStatus.LOCAL_AD_FAILED, str(exc))


def _ensure_default_role(session: Session, user_id: UUID) -> None:
    role_names = get_settings().provisioning.default_role_names
    if not role_names:
        logger.warning(
            "[PROVISIONING] Provisioning:DefaultRoleNames vacío — se omite asignación de roles."
        )
        return

    logger.info(
        "[PROVISIONING] Asignando %s rol(es) a UserId=%s: [%s]",
        len(role_names), user_id, ", ".join(role_names),
    )

    for role_name in role_names:
        if not role_name or not role_name.strip():
            continue

        role = (
            session.query(Role)
            .filter(Role.name == role_name, Role.is_active, ~Role.is_deleted)
            .first()
        )
        if role is None:
            logger.error(
                "[PROVISIONING] Rol '%s' no encontrado en auth.tbl_Roles. Verifica "
                "Provisioning:DefaultRoleNames en appsettings.json. UserId=%s",
                role_name, user_id,
            )
            continue

        already_assigned = (
            session.query(UserRole)
            .filter(
                UserRole.user_id == user_id,
                UserRole.role_id == role.id,
                ~UserRole.is_deleted,
            )
            .first()
            is not None
        )
        if already_assigned:
            logger.info(
                "[PROVISIONING] Rol '%s' ya asignado a UserId=%s — omitido.", role_name, user_id
            )
            continue

        session.add(
            UserRole(
                user_id=user_id,
                role_id=role.id,
                assigned_by="Provisioning-Automatico",
                reason="Asignación automática al aprovisionar cuenta institucional",
            )
        )
        logger.info(
            "[PROVISIONING] auth.tbl_UserRoles: RoleId=%s ('%s') → UserId=%s",
            role.id, role.name, user_id,
        )


def _ensure_default_ad_group(ad_object_id: str, email: str) -> None:
    group_id = get_settings().provisioning.grupo_funcionarios_activos_cn
    if not group_id or not group_id.strip():
        logger.info(
            "[PROVISIONING] Provisioning:GrupoFuncionariosActivosCn vacío — no se agrega "
            "a grupo AD."
        )
        return

    logger.info(
        "[PROVISIONING] Agregando funcionario '%s' (AD ObjectId=%s) al grupo '%s'...",
        email, ad_object_id, group_id,
    )
    try:
        if local_ad_service.is_user_in_group(group_id, ad_object_id):
            logger.info(
                "[PROVISIONING] Usuario '%s' ya pertenece al grupo '%s' — se omite.",
                email, group_id,
            )
            return

        local_ad_service.add_user_to_group(group_id, ad_object_id)
        logger.info("[PROVISIONING] AD Local: '%s' agregado al grupo '%s'", email, group_id)
    except Exception as exc:
        logger.error(
            "[PROVISIONING] ERROR al agregar '%s' al grupo AD '%s'. El aprovisionamiento "
            "continúa — revisa la configuración del grupo. %s",
            email, group_id, exc,
        )


def _ensure_auth_user(session: Session, email: str, display_name: str) -> User:
    existing = session.query(User).filter(User.email == email).first()
    if existing is not None:
        return existing

    user = User(
        id=uuid4(), email=email, display_name=display_name, user_type="AzureAD", is_active=True
    )
    session.add(user)
    session.flush()
    return user


def _ensure_user_employee(session: Session, user_id: UUID, email: str, hr_employee_id: int) -> None:
    exists = session.query(UserEmployee).filter(UserEmployee.employee_email == email).first()
    if exists is not None:
        return

    session.add(
        UserEmployee(
            user_id=user_id,
            employee_email=email,
            hr_employee_id=hr_employee_id,
            is_active=True,
            sync_date=datetime.now(),
            notes=f"Aprovisionado desde HrSystem (EmployeeId={hr_employee_id})",
        )
    )
    session.flush()


# ── Completar aprovisionamiento (Entra sync → licencia) ──────────────────────


def check_and_complete_provisioning(
    session: Session, provisioning_id: UUID
) -> UserProvisioningRead | None:
    record = session.get(UserProvisioning, provisioning_id)
    if record is None:
        return None

    if record.provisioning_status_id not in _COMPLETABLE_STATUSES:
        logger.info(
            "Aprovisionamiento %s ya está en status final: %s",
            provisioning_id, record.provisioning_status_name,
        )
        return _map_to_dto(record)

    _do_complete(session, record)
    return _map_to_dto(record)


def complete_pending(session: Session) -> CompletePendingResultRead:
    """Espejo de CompletePendingAsync. El .NET procesa hasta 3 concurrentes con
    SemaphoreSlim; aqui se procesa secuencialmente (misma simplificacion que
    provision_bulk — ver comentario ahi)."""
    records = (
        session.query(UserProvisioning)
        .filter(UserProvisioning.provisioning_status_id.in_(_COMPLETABLE_STATUSES))
        .order_by(UserProvisioning.created_at)
        .all()
    )
    if not records:
        return CompletePendingResultRead(
            total_processed=0, license_assigned=0, still_pending=0, failed=0, results=[]
        )

    logger.info("CompletePending: procesando %s registros pendientes", len(records))
    for record in records:
        _do_complete(session, record)

    results = [_map_to_dto(r) for r in records]
    return CompletePendingResultRead(
        total_processed=len(results),
        license_assigned=sum(
            1
            for r in results
            if r.provisioning_status_id == int(ProvisioningStatus.LICENSE_ASSIGNED)
        ),
        still_pending=sum(
            1
            for r in results
            if r.provisioning_status_id == int(ProvisioningStatus.PENDING_ENTRA_SYNC)
        ),
        failed=sum(
            1 for r in results if r.provisioning_status_id == int(ProvisioningStatus.LICENSE_FAILED)
        ),
        results=results,
    )


def _do_complete(session: Session, record: UserProvisioning) -> None:
    record.last_checked_at = datetime.now()
    record.updated_at = datetime.now()

    try:
        sync = azure_mgmt.check_user_entra_sync(record.email)
    except Exception as exc:
        logger.warning("Error al verificar Entra sync para %s: %s", record.email, exc)
        record.error_message = f"Error al verificar Entra sync: {exc}"
        session.commit()
        return

    if sync.status in (EntraSyncStatus.PENDING_SYNC, EntraSyncStatus.UNKNOWN):
        record.provisioning_status_id = int(ProvisioningStatus.PENDING_ENTRA_SYNC)
        record.provisioning_status_name = _status_name(ProvisioningStatus.PENDING_ENTRA_SYNC)
        record.error_message = sync.message
        session.commit()
        logger.info("Empleado %s aún pendiente de sync Entra", record.email)
        return

    if sync.azure_object_id:
        record.entra_object_id = sync.azure_object_id

    record.provisioning_status_id = int(ProvisioningStatus.SYNCED_IN_ENTRA)
    record.provisioning_status_name = _status_name(ProvisioningStatus.SYNCED_IN_ENTRA)
    record.error_message = None
    session.commit()

    logger.info(
        "Empleado %s sincronizado en Entra. Procediendo a asignar licencia.", record.email
    )

    try:
        license_result = license_service.assign_employee_license(session, record.email, "EC")
    except Exception as exc:
        logger.error("Excepción al asignar licencia para %s: %s", record.email, exc)
        record.provisioning_status_id = int(ProvisioningStatus.LICENSE_FAILED)
        record.provisioning_status_name = _status_name(ProvisioningStatus.LICENSE_FAILED)
        record.error_message = str(exc)
        session.commit()
        return

    if license_result.success:
        record.license_sku_id = license_result.sku_part_number
        record.license_assigned_at = datetime.now()
        record.provisioning_status_id = int(ProvisioningStatus.LICENSE_ASSIGNED)
        record.provisioning_status_name = _status_name(ProvisioningStatus.LICENSE_ASSIGNED)
        record.error_message = None
        logger.info("Licencia %s asignada a %s", license_result.sku_part_number, record.email)
    else:
        record.provisioning_status_id = int(ProvisioningStatus.LICENSE_FAILED)
        record.provisioning_status_name = _status_name(ProvisioningStatus.LICENSE_FAILED)
        record.error_message = license_result.message
        logger.warning("Fallo al asignar licencia a %s: %s", record.email, license_result.message)

    record.updated_at = datetime.now()
    session.commit()


# ── Restablecimiento de contraseña ───────────────────────────────────────────


def _generate_temporary_password() -> str:
    """Espejo de GenerateTemporaryPassword — mismo charset/longitud (12) que el
    .NET, pero usando `secrets` (CSPRNG) en vez de `Random.Shared`: el .NET
    original usa un generador NO criptografico para una contraseña real de
    usuario, una debilidad real que no tiene sentido replicar a proposito."""
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    lower = "abcdefghjkmnpqrstuvwxyz"
    digits = "23456789"
    special = "!@#$%&*"
    all_chars = upper + lower + digits + special

    chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    chars.extend(secrets.choice(all_chars) for _ in range(4, 12))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def reset_password(session: Session, provisioning_id: UUID) -> PasswordResetResultRead | None:
    record = session.get(UserProvisioning, provisioning_id)
    if record is None:
        return None

    if not record.local_ad_object_id or not record.local_ad_object_id.strip():
        raise ValueError(
            f"El empleado no tiene cuenta en AD Local (aprovisionamiento id={provisioning_id})."
        )

    new_password = _generate_temporary_password()
    local_ad_service.change_user_password(
        record.local_ad_object_id, new_password, force_password_change=True
    )

    record.updated_at = datetime.now()
    session.commit()

    logger.info(
        "Contraseña restablecida en AD Local para EmpleadoHR=%s, Email=%s",
        record.hr_employee_id, record.email,
    )
    return PasswordResetResultRead(
        provisioning_id=str(record.id),
        hr_employee_id=record.hr_employee_id,
        email=record.email,
        new_temporary_password=new_password,
        message="Contraseña restablecida en AD Local. El usuario deberá cambiarla en el "
        "próximo inicio de sesión.",
    )


# ── Deshabilitar cuenta ───────────────────────────────────────────────────────


def disable_employee(session: Session, hr_employee_id: int) -> DisableEmployeeResultRead:
    logger.info("[DISABLE] Iniciando deshabilitar cuenta. HrEmployeeId=%s", hr_employee_id)

    user_employee = (
        session.query(UserEmployee)
        .filter(
            UserEmployee.hr_employee_id == hr_employee_id, UserEmployee.is_active
        )
        .first()
    )
    if user_employee is None:
        logger.warning(
            "[DISABLE] No se encontró cuenta activa para HrEmployeeId=%s", hr_employee_id
        )
        return DisableEmployeeResultRead(
            success=False, hr_employee_id=hr_employee_id, email=None,
            error_message="No se encontró cuenta activa para este empleado.",
        )

    user = session.get(User, user_employee.user_id)
    if user is None:
        logger.warning(
            "[DISABLE] auth.tbl_Users no encontrado para UserId=%s", user_employee.user_id
        )
        return DisableEmployeeResultRead(
            success=False, hr_employee_id=hr_employee_id, email=user_employee.employee_email,
            error_message="Usuario no encontrado en auth.tbl_Users.",
        )

    provisioning = (
        session.query(UserProvisioning)
        .filter(
            UserProvisioning.hr_employee_id == hr_employee_id,
            UserProvisioning.local_ad_object_id.isnot(None),
            UserProvisioning.local_ad_object_id != "",
        )
        .order_by(UserProvisioning.provisioned_at.desc())
        .first()
    )
    ad_identifier = (
        provisioning.local_ad_object_id
        if provisioning is not None
        else user_employee.employee_email
    )

    settings = get_settings()
    student_type_ids = settings.provisioning.student_employee_type_ids
    is_student = (
        provisioning is not None
        and bool(student_type_ids)
        and provisioning.employee_type_id in student_type_ids
    )

    ad_settings = settings.local_ad
    inactivos_ou = (
        ad_settings.estudiantes_inactivos_ou
        if is_student
        else ad_settings.funcionarios_inactivos_ou
    )
    grupo_activos = (
        settings.provisioning.grupo_estudiantes_activos_cn
        if is_student
        else settings.provisioning.grupo_funcionarios_activos_cn
    )
    tipo_persona = "estudiante" if is_student else "funcionario"

    try:
        local_ad_service.set_user_enabled(ad_identifier, False)
        logger.info(
            "[DISABLE] Cuenta deshabilitada en AD (%s). Identifier=%s", tipo_persona, ad_identifier
        )

        if inactivos_ou and inactivos_ou.strip():
            try:
                local_ad_service.move_user_to_ou(ad_identifier, inactivos_ou)
                logger.info(
                    "[DISABLE] Usuario movido a OU Inactivos (%s). Identifier=%s",
                    inactivos_ou, ad_identifier,
                )
            except Exception as move_ex:
                logger.warning(
                    "[DISABLE] No se pudo mover a OU Inactivos (%s). Identifier=%s — %s",
                    inactivos_ou, ad_identifier, move_ex,
                )
        else:
            logger.warning(
                "[DISABLE] OU Inactivos no configurada para tipo '%s' — se omite movimiento.",
                tipo_persona,
            )

        if grupo_activos and grupo_activos.strip():
            try:
                local_ad_service.remove_user_from_group(grupo_activos, ad_identifier)
                logger.info(
                    "[DISABLE] Usuario quitado del grupo %s. Identifier=%s",
                    grupo_activos, ad_identifier,
                )
            except Exception as grp_ex:
                logger.warning(
                    "[DISABLE] No se pudo quitar del grupo %s. Identifier=%s — %s",
                    grupo_activos, ad_identifier, grp_ex,
                )
    except Exception as ad_ex:
        logger.error(
            "[DISABLE] Error al deshabilitar en AD Local. Identifier=%s — %s",
            ad_identifier, ad_ex,
        )
        return DisableEmployeeResultRead(
            success=False, hr_employee_id=hr_employee_id, email=user_employee.employee_email,
            error_message=f"Error en AD Local: {ad_ex}",
        )

    user.is_active = False
    session.commit()

    logger.info(
        "[DISABLE] Cuenta deshabilitada. HrEmployeeId=%s | Email=%s",
        hr_employee_id, user_employee.employee_email,
    )
    return DisableEmployeeResultRead(
        success=True, hr_employee_id=hr_employee_id, email=user_employee.employee_email,
        error_message=None,
    )


def disable_by_provisioning_id(
    session: Session, provisioning_id: UUID
) -> DisableEmployeeResultRead | None:
    provisioning = session.get(UserProvisioning, provisioning_id)
    if provisioning is None:
        logger.warning(
            "[DISABLE] Registro de aprovisionamiento no encontrado. ProvisioningId=%s",
            provisioning_id,
        )
        return None
    return disable_employee(session, provisioning.hr_employee_id)


def disable_by_ad_id(session: Session, ad_object_id: str) -> DisableEmployeeResultRead | None:
    if not ad_object_id or not ad_object_id.strip():
        return None

    provisioning = (
        session.query(UserProvisioning)
        .filter(UserProvisioning.local_ad_object_id == ad_object_id)
        .order_by(UserProvisioning.provisioned_at.desc())
        .first()
    )
    if provisioning is None:
        logger.warning(
            "[DISABLE] Sin registro de aprovisionamiento para AD ObjectId=%s", ad_object_id
        )
        return None
    return disable_employee(session, provisioning.hr_employee_id)
