from repositoryuta.repositories.sync_log_repository import SyncLogRepository
from repositoryuta.schemas.audit import SyncLogCreate


def test_log_azure_sync_and_hr_sync_are_separate_tables(sqlite_session) -> None:
    repo = SyncLogRepository(sqlite_session)

    azure_row = repo.log_azure_sync(SyncLogCreate(sync_type="Auto", records_processed=10))
    hr_row = repo.log_hr_sync(SyncLogCreate(sync_type="Manual", records_processed=5))

    assert azure_row.id is not None
    assert azure_row.records_processed == 10
    assert hr_row.id is not None
    assert hr_row.sync_type == "Manual"
