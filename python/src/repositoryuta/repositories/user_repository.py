from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from repositoryuta.models.identity import (
    LocalUserCredential,
    PasswordHistory,
    SecurityToken,
    User,
    UserAccountLock,
    UserActivityLog,
    UserEmployee,
    UserProvisioning,
)
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.models.session import UserSession


class UserRepository:
    """Espejo de UserRepository (Data/Repositories/_Specialized.cs) + el borrado
    en cascada que hoy vive mal ubicado en UsersController.Delete (regla de
    Fase 0 #1: mismo orden exacto de tablas, movido a la capa correcta)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_email(self, email: str) -> User | None:
        return self._session.scalar(select(User).where(User.email == email))

    def find_by_id(self, user_id: UUID) -> User | None:
        return self._session.get(User, user_id)

    def get_local_credential(self, user_id: UUID) -> LocalUserCredential | None:
        return self._session.get(LocalUserCredential, user_id)

    def set_last_login(self, user_id: UUID, when: datetime) -> None:
        user = self._session.get(User, user_id)
        if user is not None:
            user.last_login = when

    def sync_azure_object_id(self, user_id: UUID, azure_object_id: UUID) -> None:
        user = self._session.get(User, user_id)
        if user is not None and user.azure_object_id != azure_object_id:
            user.azure_object_id = azure_object_id

    def get_roles(self, user_id: UUID) -> list[str]:
        """Espejo de UserRepository.GetRolesAsync. El filtro `UserRole.is_deleted`
        es manual a proposito (UserRole no implementa ISoftDeletable en .NET);
        `Role.is_deleted`/`Role.is_active` tambien se repiten aqui aunque Role SI
        tiene el filtro automatico alla, para no depender de un comportamiento
        implicito que en Python no existe.
        """
        now = datetime.now()
        stmt = (
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == user_id,
                ~UserRole.is_deleted,
                Role.is_active,
                ~Role.is_deleted,
                (UserRole.expires_at.is_(None)) | (UserRole.expires_at > now),
            )
        )
        return list(self._session.scalars(stmt))

    def get_hr_employee_id(self, user_id: UUID) -> int | None:
        stmt = select(UserEmployee.hr_employee_id).where(UserEmployee.user_id == user_id)
        return self._session.scalar(stmt)

    def get_personnel_email(self, user_id: UUID) -> str | None:
        stmt = select(UserEmployee.employee_email).where(
            UserEmployee.user_id == user_id, UserEmployee.is_active
        )
        return self._session.scalar(stmt)

    def delete_with_cascade(self, user_id: UUID) -> bool:
        """Espejo EXACTO de UsersController.Delete: mismo orden de 8 tablas
        relacionadas antes de borrar la fila de User. No reordenar ni omitir
        pasos — es el contrato a preservar (regla de Fase 0 #1).
        """
        user = self._session.get(User, user_id)
        if user is None:
            return False

        self._session.execute(delete(UserEmployee).where(UserEmployee.user_id == user_id))
        self._session.execute(delete(UserRole).where(UserRole.user_id == user_id))
        self._session.execute(delete(UserSession).where(UserSession.user_id == user_id))
        self._session.execute(delete(SecurityToken).where(SecurityToken.user_id == user_id))
        self._session.execute(delete(PasswordHistory).where(PasswordHistory.user_id == user_id))
        self._session.execute(delete(UserAccountLock).where(UserAccountLock.user_id == user_id))
        self._session.execute(delete(UserActivityLog).where(UserActivityLog.user_id == user_id))
        self._session.execute(
            delete(UserProvisioning).where(UserProvisioning.auth_user_id == user_id)
        )

        local_credential = self._session.get(LocalUserCredential, user_id)
        if local_credential is not None:
            self._session.delete(local_credential)

        self._session.delete(user)
        return True
