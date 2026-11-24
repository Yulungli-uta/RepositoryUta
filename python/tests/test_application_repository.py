from datetime import datetime
from uuid import uuid4

from repositoryuta.models.application import Application
from repositoryuta.models.views import VwActiveApiClient
from repositoryuta.repositories.application_repository import ApplicationRepository
from repositoryuta.schemas.application import LegacyAuthLogCreate


def test_exists_active_client_true_and_false_cases(sqlite_session) -> None:
    sqlite_session.add_all(
        [
            Application(
                name="uta-signature",
                client_id="uta-signature",
                client_secret_hash="hash",
                is_active=True,
            ),
            Application(
                name="app-suspendida",
                client_id="app-suspendida",
                client_secret_hash="hash",
                is_active=False,
            ),
        ]
    )
    sqlite_session.flush()

    repo = ApplicationRepository(sqlite_session)

    assert repo.exists_active_client("uta-signature") is True
    assert repo.exists_active_client("app-suspendida") is False
    assert repo.exists_active_client("no-existe") is False


def test_log_legacy_auth(sqlite_session) -> None:
    repo = ApplicationRepository(sqlite_session)

    row = repo.log_legacy_auth(
        LegacyAuthLogCreate(
            application_id=uuid4(), user_email="juan@uta.edu.ec", auth_result="Success"
        )
    )

    assert row.id is not None
    assert row.auth_result == "Success"


def test_get_active_api_clients_orders_by_last_used_then_name(sqlite_session) -> None:
    sqlite_session.add_all(
        [
            VwActiveApiClient(
                id=uuid4(),
                name="uta-signature",
                client_id="uta-signature",
                is_active=True,
                created_at=datetime(2026, 1, 1),
                last_used_at=datetime(2026, 3, 1),
                calls_last_24h=5,
            ),
            VwActiveApiClient(
                id=uuid4(),
                name="legacy-erp-client",
                client_id="legacy-erp-client",
                is_active=True,
                created_at=datetime(2026, 1, 1),
                last_used_at=None,
                calls_last_24h=0,
            ),
        ]
    )
    sqlite_session.flush()

    clients = ApplicationRepository(sqlite_session).get_active_api_clients()

    assert next(c.name for c in clients) == "uta-signature"
