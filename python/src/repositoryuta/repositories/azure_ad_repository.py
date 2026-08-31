from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.audit import AzureSyncLog
from repositoryuta.models.identity import User


class AzureAdRepository:
    """Espejo de AzureAdRepository (Data/Repositories/_Specialized.cs)."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_azure_id(self, azure_object_id: UUID) -> User | None:
        return self._session.scalar(select(User).where(User.azure_object_id == azure_object_id))

    def create_or_update_from_azure(
        self, azure_object_id: str, email: str, display_name: str
    ) -> User:
        azure_guid = UUID(azure_object_id)
        user = self.find_by_azure_id(azure_guid)

        if user is None:
            user = User(
                id=uuid4(),
                email=email,
                display_name=display_name,
                azure_object_id=azure_guid,
                user_type="AzureAD",
                is_active=True,
                created_at=datetime.now(),
            )
            self._session.add(user)
        else:
            user.email = email
            user.display_name = display_name
            user.is_active = True

        self._session.flush()
        return user

    def log_azure_sync(
        self, sync_type: str, processed: int, created: int, updated: int, errors: int, details: str
    ) -> None:
        row = AzureSyncLog(
            sync_type=sync_type,
            records_processed=processed,
            new_users=created,
            updated_users=updated,
            errors=errors,
            details=details,
        )
        self._session.add(row)
        self._session.flush()
