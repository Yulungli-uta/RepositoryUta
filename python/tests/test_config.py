import pytest
from pydantic import ValidationError

from repositoryuta.config import Settings


def test_production_requires_database_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)

    with pytest.raises(ValidationError, match="DATABASE_URL_FILE es obligatorio"):
        Settings()


def test_azure_client_secret_loaded_from_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_file = tmp_path / "azure-secret.txt"
    secret_file.write_text("s3cr3t\n", encoding="utf-8")
    db_file = tmp_path / "db.txt"
    db_file.write_text("sqlite://", encoding="utf-8")

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL_FILE", str(db_file))
    monkeypatch.setenv("AZURE_AD__CLIENT_SECRET_FILE", str(secret_file))

    settings = Settings()

    assert settings.azure_ad.client_secret == "s3cr3t"


def test_local_ad_password_file_missing_fails_in_production(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_file = tmp_path / "db.txt"
    db_file.write_text("sqlite://", encoding="utf-8")
    missing_file = tmp_path / "does-not-exist.txt"

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL_FILE", str(db_file))
    monkeypatch.setenv("LOCAL_AD__SERVICE_ACCOUNT_PASSWORD_FILE", str(missing_file))

    with pytest.raises(ValidationError, match="LOCAL_AD__SERVICE_ACCOUNT_PASSWORD_FILE"):
        Settings()
