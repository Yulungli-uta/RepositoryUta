import pytest
from pydantic import ValidationError

from repositoryuta.config import Settings


def test_production_requires_database_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)

    with pytest.raises(ValidationError, match="DATABASE_URL_FILE es obligatorio"):
        Settings()
