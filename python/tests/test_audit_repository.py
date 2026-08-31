from uuid import uuid4

from repositoryuta.repositories.audit_repository import AuditRepository
from repositoryuta.schemas.audit import (
    AuditLogCreate,
    LoginHistoryCreate,
    PermissionChangeHistoryCreate,
    RoleChangeHistoryCreate,
)


def test_log_action_persists_a_row(sqlite_session) -> None:
    repo = AuditRepository(sqlite_session)

    row = repo.log_action(
        AuditLogCreate(action="UserDeleted", module="Users", entity_id=str(uuid4()))
    )

    assert row.id is not None
    assert row.action == "UserDeleted"


def test_insert_login_persists_a_row(sqlite_session) -> None:
    repo = AuditRepository(sqlite_session)

    row = repo.insert_login(LoginHistoryCreate(login_type="Local", login_status="Success"))

    assert row.id is not None
    assert row.login_status == "Success"


def test_log_role_change_and_permission_change(sqlite_session) -> None:
    repo = AuditRepository(sqlite_session)
    user_id = uuid4()

    role_change = repo.log_role_change(
        RoleChangeHistoryCreate(
            user_id=user_id, role_id=1, change_type="Assigned", changed_by="admin@uta.edu.ec"
        )
    )
    permission_change = repo.log_permission_change(
        PermissionChangeHistoryCreate(
            role_id=1, permission_id=2, change_type="Added", changed_by="admin@uta.edu.ec"
        )
    )

    assert role_change.id is not None
    assert permission_change.id is not None
