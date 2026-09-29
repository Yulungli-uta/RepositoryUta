from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from repositoryuta.core.exceptions import NotFoundError
from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole, UserAccessProfile
from repositoryuta.models.rbac import UserRole
from repositoryuta.repositories.access_profile_repository import AccessProfileRepository
from repositoryuta.schemas.rbac import UserRoleCreate
from repositoryuta.services.crud_service import CrudService


def get_assigned_profiles(session: Session, user_id: UUID) -> list[AccessProfile]:
    """Espejo de GetAssignedProfilesAsync: perfiles activos asignados a un
    usuario — informativo, no participa en la resolucion de permisos."""
    return AccessProfileRepository(session).get_profiles_for_user(user_id)


def assign(
    session: Session, user_id: UUID, access_profile_id: int, assigned_by: str | None
) -> None:
    """Espejo de AccessProfileAssignmentService.AssignAsync: expande el perfil
    a filas UserRole concretas, reutilizando el CrudService generico de
    UserRole (igual que .NET reutiliza ICrudService<UserRole,...>)."""
    profile = session.scalar(
        select(AccessProfile).where(
            AccessProfile.id == access_profile_id, ~AccessProfile.is_deleted
        )
    )
    if profile is None:
        raise NotFoundError(f"AccessProfile {access_profile_id} no existe.")

    role_ids = list(
        session.scalars(
            select(AccessProfileRole.role_id).where(
                AccessProfileRole.access_profile_id == access_profile_id
            )
        )
    )
    source = f"Profile:{access_profile_id}"
    user_roles = CrudService(session, UserRole)

    for role_id in role_ids:
        try:
            with session.begin_nested():
                user_roles.create(
                    UserRoleCreate(
                        user_id=user_id,
                        role_id=role_id,
                        assigned_by=assigned_by,
                        reason=f"Perfil: {profile.name}",
                        assigned_via=source,
                    )
                )
        except IntegrityError:
            # El usuario ya tiene este rol activo (asignado directo o por otro
            # perfil). No se duplica ni se sobreescribe su origen.
            continue

    profiles = CrudService(session, UserAccessProfile)
    existing_assignment = profiles.get(user_id, access_profile_id)
    if existing_assignment is None:
        session.add(
            UserAccessProfile(
                user_id=user_id, access_profile_id=access_profile_id, assigned_by=assigned_by
            )
        )
        session.flush()
    elif existing_assignment.is_deleted:
        existing_assignment.is_deleted = False
        existing_assignment.assigned_at = datetime.now()
        existing_assignment.assigned_by = assigned_by
        session.flush()


def unassign(
    session: Session, user_id: UUID, access_profile_id: int, removed_by: str | None
) -> None:
    """Espejo de AccessProfileAssignmentService.UnassignAsync: solo revoca los
    roles que vinieron de ESTE perfil y que ningun otro perfil activo del
    usuario tambien otorga.

    `removed_by` se recibe pero no se usa aqui — igual que en el .NET real,
    donde el parametro homonimo tampoco se usa dentro del servicio (el log de
    auditoria con RemovedBy lo arma el controller/router, no el servicio).
    """
    assignment = CrudService(session, UserAccessProfile).get(user_id, access_profile_id)
    if assignment is None or assignment.is_deleted:
        return

    role_ids = list(
        session.scalars(
            select(AccessProfileRole.role_id).where(
                AccessProfileRole.access_profile_id == access_profile_id
            )
        )
    )
    source = f"Profile:{access_profile_id}"
    user_roles = CrudService(session, UserRole)

    for role_id in role_ids:
        covered_by_other_profile = (
            session.scalar(
                select(UserAccessProfile.access_profile_id)
                .join(
                    AccessProfileRole,
                    AccessProfileRole.access_profile_id == UserAccessProfile.access_profile_id,
                )
                .where(
                    UserAccessProfile.user_id == user_id,
                    ~UserAccessProfile.is_deleted,
                    UserAccessProfile.access_profile_id != access_profile_id,
                    AccessProfileRole.role_id == role_id,
                )
                .limit(1)
            )
            is not None
        )
        if covered_by_other_profile:
            continue  # otro perfil activo del usuario tambien otorga este rol

        user_role = session.get(UserRole, (user_id, role_id))
        # Solo se revoca si el rol vino de ESTE perfil; si fue asignado directo
        # o por otro mecanismo, se deja intacto.
        if user_role is not None and not user_role.is_deleted and user_role.assigned_via == source:
            user_roles.delete(user_id, role_id)

    assignment.is_deleted = True
    session.flush()
