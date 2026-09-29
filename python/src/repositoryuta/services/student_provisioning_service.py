import logging

from sqlalchemy.orm import Session

from repositoryuta.config import get_settings
from repositoryuta.schemas.provisioning import (
    CreateStudentAdAccountRequest,
    CreateStudentAdAccountResultRead,
    DisableStudentAdAccountResultRead,
)
from repositoryuta.services import institutional_email_service, local_ad_service
from repositoryuta.services.local_ad_service import DirectoryUser

logger = logging.getLogger(__name__)

# Espejo de StudentProvisioningService.cs. No persiste en RepositoryUta — el
# estado del aprovisionamiento vive en HrBackend.tbl_StudentProvisioning; aqui
# solo se ejecuta la operacion en AD Local y se retorna el resultado.


def create_ad_account(
    session: Session, req: CreateStudentAdAccountRequest
) -> CreateStudentAdAccountResultRead:
    logger.info(
        "[STUDENT-AD] Creando cuenta AD. HrStudentId=%s | Nombre=%s",
        req.hr_student_id, req.display_name,
    )

    ad_settings = get_settings().local_ad
    try:
        email = institutional_email_service.generate_available_email(
            session, req.hr_student_id, req.given_name, req.surname, ad_settings.base_dn
        )
    except Exception as exc:
        logger.error(
            "[STUDENT-AD] Error al generar email para HrStudentId=%s: %s",
            req.hr_student_id, exc,
        )
        return CreateStudentAdAccountResultRead(
            success=False, ad_object_id=None, email=None, error_message=str(exc)
        )

    try:
        dir_user = DirectoryUser(
            id="", email=email, display_name=req.display_name, given_name=req.given_name,
            surname=req.surname, job_title=None, department=None, is_enabled=True,
            id_card=req.id_card,
        )

        created = local_ad_service.create_user(
            dir_user, req.initial_password, ad_settings.estudiantes_activos_ou,
            req.force_password_change,
        )

        logger.info(
            "[STUDENT-AD] Cuenta creada. HrStudentId=%s | Email=%s | AdObjectId=%s",
            req.hr_student_id, email, created.id,
        )

        _try_add_to_group(created.id, req.hr_student_id)

        return CreateStudentAdAccountResultRead(
            success=True, ad_object_id=created.id, email=email, error_message=None
        )
    except Exception as exc:
        logger.error(
            "[STUDENT-AD] Error al crear cuenta en AD. HrStudentId=%s: %s",
            req.hr_student_id, exc,
        )
        return CreateStudentAdAccountResultRead(
            success=False, ad_object_id=None, email=email, error_message=str(exc)
        )


def disable_ad_account(ad_object_id: str) -> DisableStudentAdAccountResultRead:
    logger.info("[STUDENT-AD] Deshabilitando cuenta AD. AdObjectId=%s", ad_object_id)

    settings = get_settings()
    try:
        local_ad_service.set_user_enabled(ad_object_id, False)
        logger.info("[STUDENT-AD] Cuenta deshabilitada. AdObjectId=%s", ad_object_id)

        inactivos_ou = settings.local_ad.estudiantes_inactivos_ou
        if inactivos_ou and inactivos_ou.strip():
            try:
                local_ad_service.move_user_to_ou(ad_object_id, inactivos_ou)
                logger.info("[STUDENT-AD] Movido a OU Inactivos. AdObjectId=%s", ad_object_id)
            except Exception as move_ex:
                logger.warning(
                    "[STUDENT-AD] No se pudo mover a OU Inactivos. AdObjectId=%s — %s",
                    ad_object_id, move_ex,
                )

        grupo_activos = settings.provisioning.grupo_estudiantes_activos_cn
        if grupo_activos and grupo_activos.strip():
            try:
                local_ad_service.remove_user_from_group(grupo_activos, ad_object_id)
                logger.info("[STUDENT-AD] Quitado del grupo EActivos. AdObjectId=%s", ad_object_id)
            except Exception as grp_ex:
                logger.warning(
                    "[STUDENT-AD] No se pudo quitar del grupo EActivos. AdObjectId=%s — %s",
                    ad_object_id, grp_ex,
                )

        return DisableStudentAdAccountResultRead(
            success=True, ad_object_id=ad_object_id, error_message=None
        )
    except Exception as exc:
        logger.error(
            "[STUDENT-AD] Error deshabilitando cuenta. AdObjectId=%s — %s", ad_object_id, exc
        )
        return DisableStudentAdAccountResultRead(
            success=False, ad_object_id=ad_object_id, error_message=str(exc)
        )


def _try_add_to_group(ad_object_id: str, hr_student_id: int) -> None:
    group_cn = get_settings().provisioning.grupo_estudiantes_activos_cn
    if not group_cn or not group_cn.strip():
        return

    try:
        groups = local_ad_service.list_groups(name_filter=group_cn)
        group = groups[0] if groups else None
        if group is not None:
            local_ad_service.add_user_to_group(group.id, ad_object_id)
            logger.info(
                "[STUDENT-AD] Agregado al grupo %s. HrStudentId=%s", group_cn, hr_student_id
            )
        else:
            logger.warning("[STUDENT-AD] Grupo '%s' no encontrado en AD.", group_cn)
    except Exception as exc:
        logger.warning(
            "[STUDENT-AD] No se pudo agregar al grupo %s. HrStudentId=%s — %s",
            group_cn, hr_student_id, exc,
        )
