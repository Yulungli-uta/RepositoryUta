from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.access_profile import AccessProfile, AccessProfileRole, UserAccessProfile
from repositoryuta.models.rbac import Role
from repositoryuta.schemas.access_profile import UserAccessProfileCreate


class AccessProfileRepository:
    """Persistencia de AccessProfile/AccessProfileRole/UserAccessProfile.

    La expansion real de un perfil a filas UserRole (IAccessProfileAssignmentService)
    es logica de negocio y pertenece a Fase 4 — aqui solo el registro de
    trazabilidad (UserAccessProfile) y las lecturas de composicion.

    is_deleted se filtra a mano en list_active/get_profiles_for_user: ni
    AccessProfile ni UserAccessProfile implementan ISoftDeletable en .NET
    (confirmado en _Entities.cs), pero la columna existe con esa intencion.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_active(self) -> list[AccessProfile]:
        stmt = select(AccessProfile).where(~AccessProfile.is_deleted)
        return list(self._session.scalars(stmt))

    def get_roles_for_profile(self, access_profile_id: int) -> list[Role]:
        stmt = (
            select(Role)
            .join(AccessProfileRole, AccessProfileRole.role_id == Role.id)
            .where(AccessProfileRole.access_profile_id == access_profile_id)
        )
        return list(self._session.scalars(stmt))

    def get_profiles_for_user(self, user_id: UUID) -> list[AccessProfile]:
        stmt = (
            select(AccessProfile)
            .join(
                UserAccessProfile, UserAccessProfile.access_profile_id == AccessProfile.id
            )
            .where(
                UserAccessProfile.user_id == user_id,
                ~UserAccessProfile.is_deleted,
                ~AccessProfile.is_deleted,
            )
        )
        return list(self._session.scalars(stmt))

    def record_assignment(self, data: UserAccessProfileCreate) -> UserAccessProfile:
        row = UserAccessProfile(**data.model_dump())
        self._session.add(row)
        self._session.flush()
        return row
