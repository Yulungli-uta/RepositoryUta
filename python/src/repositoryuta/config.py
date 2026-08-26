from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "RepositoryUta"
    app_version: str = "0.1.0"
    app_env: Literal["development", "test", "validation", "production"] = "validation"
    root_path: str = "/WsSeguUta"
    log_level: str = "INFO"

    database_url: str | None = Field(default=None, repr=False)
    database_url_file: Path | None = None
    db_pool_size: int = Field(default=5, ge=1, le=20)
    db_max_overflow: int = Field(default=5, ge=0, le=20)
    db_pool_timeout_seconds: int = Field(default=10, ge=1, le=60)
    db_pool_recycle_seconds: int = Field(default=1800, ge=60, le=7200)

    @model_validator(mode="after")
    def load_and_validate_secrets(self) -> "Settings":
        if self.database_url_file:
            try:
                self.database_url = self.database_url_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                if self.app_env == "production":
                    raise ValueError("No se pudo leer DATABASE_URL_FILE") from exc
                self.database_url = None

        if self.app_env == "production" and not self.database_url_file:
            raise ValueError("DATABASE_URL_FILE es obligatorio en production")
        return self

    @property
    def docs_enabled(self) -> bool:
        return self.app_env in {"development", "test", "validation"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
