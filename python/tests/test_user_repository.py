from datetime import datetime, timedelta
from uuid import uuid4

from repositoryuta.models.identity import PasswordHistory, SecurityToken, User, UserEmployee
from repositoryuta.models.rbac import Role, UserRole
from repositoryuta.repositories.user_repository import UserRepository


def _make_user(session, **overrides) -> User:
    user = User(id=uuid4(), email="juan.perez@uta.edu.ec", display_name="Juan Perez")
    for key, value in overrides.items():
        setattr(user, key, value)
    session.add(user)
    session.flush()
    return user


def test_find_by_email_and_by_id(sqlite_session) -> None:
    user = _make_user(sqlite_session)
    repo = UserRepository(sqlite_session)

    assert repo.find_by_email("juan.perez@uta.edu.ec").id == user.id
    assert repo.find_by_id(user.id).id == user.id
    assert repo.find_by_email("no-existe@uta.edu.ec") is None


def test_get_roles_excludes_expired_and_soft_deleted(sqlite_session) -> None:
    user = _make_user(sqlite_session)
    role_active = Role(name="R_EMPLOYEE", priority=100)
    role_deleted_assignment = Role(name="R_RH", priority=50)
    role_expired = Role(name="R_GUARDIAS", priority=10)
    sqlite_session.add_all([role_active, role_deleted_assignment, role_expired])
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserRole(user_id=user.id, role_id=role_active.id),
            UserRole(user_id=user.id, role_id=role_deleted_assignment.id, is_deleted=True),
            UserRole(
                user_id=user.id,
                role_id=role_expired.id,
                expires_at=datetime.now() - timedelta(days=1),
            ),
        ]
    )
    sqlite_session.flush()

    roles = UserRepository(sqlite_session).get_roles(user.id)

    assert roles == ["R_EMPLOYEE"]


def test_delete_with_cascade_removes_dependent_rows_and_the_user(sqlite_session) -> None:
    user = _make_user(sqlite_session)
    role = Role(name="R_EMPLOYEE")
    sqlite_session.add(role)
    sqlite_session.flush()

    sqlite_session.add_all(
        [
            UserEmployee(user_id=user.id, employee_email="juan@uta.edu.ec", hr_employee_id=1),
            UserRole(user_id=user.id, role_id=role.id),
            SecurityToken(
                user_id=user.id,
                token_hash="hash",
                expires_at=datetime.now() + timedelta(hours=1),
            ),
            PasswordHistory(user_id=user.id, password_hash="old-hash"),
        ]
    )
    sqlite_session.flush()

    repo = UserRepository(sqlite_session)
    deleted = repo.delete_with_cascade(user.id)
    sqlite_session.flush()

    assert deleted is True
    assert repo.find_by_id(user.id) is None
    assert sqlite_session.query(UserEmployee).filter_by(user_id=user.id).count() == 0
    assert sqlite_session.query(UserRole).filter_by(user_id=user.id).count() == 0
    assert sqlite_session.query(SecurityToken).filter_by(user_id=user.id).count() == 0
    assert sqlite_session.query(PasswordHistory).filter_by(user_id=user.id).count() == 0


def test_delete_with_cascade_returns_false_for_unknown_user(sqlite_session) -> None:
    assert UserRepository(sqlite_session).delete_with_cascade(uuid4()) is False


def test_set_last_login_and_sync_azure_object_id(sqlite_session) -> None:
    user = _make_user(sqlite_session)
    repo = UserRepository(sqlite_session)
    when = datetime(2026, 1, 1, 12, 0, 0)
    azure_id = uuid4()

    repo.set_last_login(user.id, when)
    repo.sync_azure_object_id(user.id, azure_id)
    sqlite_session.flush()

    refreshed = repo.find_by_id(user.id)
    assert refreshed.last_login == when
    assert refreshed.azure_object_id == azure_id


def test_get_local_credential_hr_employee_id_and_personnel_email(sqlite_session) -> None:
    from repositoryuta.models.identity import LocalUserCredential

    user = _make_user(sqlite_session)
    sqlite_session.add(
        LocalUserCredential(
            user_id=user.id, password_hash="hash", password_created_at=datetime.now()
        )
    )
    sqlite_session.add(
        UserEmployee(
            user_id=user.id,
            employee_email="juan.trabajo@uta.edu.ec",
            hr_employee_id=99,
            is_active=True,
        )
    )
    sqlite_session.flush()

    repo = UserRepository(sqlite_session)

    assert repo.get_local_credential(user.id).password_hash == "hash"
    assert repo.get_hr_employee_id(user.id) == 99
    assert repo.get_personnel_email(user.id) == "juan.trabajo@uta.edu.ec"
