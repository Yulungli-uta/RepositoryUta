from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(path: Path | None, *, production: bool, label: str) -> str | None:
    if path is None:
        return None
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        if production:
            raise ValueError(f"No se pudo leer {label}") from exc
        return None


class JwtSettings(BaseModel):
    key_id: str = "wssegu-uta-key-1"
    issuer: str = "WsSeguUta.AuthSystem.API"
    audience: str = "WsSeguUta.AuthSystem.API"
    private_key_path: Path | None = None
    private_key_pem: str | None = Field(default=None, repr=False)
    # Fallback estatico; en produccion el valor real se lee de auth.tbl_AppParams (Fase 4).
    # Sincronizado a 60 min 2026-09-28 (ver auth.tbl_AppParams['Jwt:AccessTokenLifetimeMinutes']).
    access_token_lifetime_minutes: int = Field(default=60, ge=1, le=1440)


class CorsSettings(BaseModel):
    policy_name: str = "WsSeguUta"
    origins: list[str] = Field(default_factory=list)
    allow_credentials: bool = True
    allowed_headers: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=list)
    preflight_max_age_seconds: int = Field(default=43200, ge=0)


class AzureAdSettings(BaseModel):
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = Field(default=None, repr=False)
    client_secret_file: Path | None = None
    redirect_uri: str | None = None
    secure_token_delivery: bool = True
    allowed_domain: str | None = None
    # Pagina de HrFrontend (mismo origen que la pestana que abrio el popup) a la
    # que se redirige el popup tras el callback, para avisar via BroadcastChannel
    # en vez de window.opener.postMessage — este ultimo no sobrevive a que el
    # popup navegue por login.microsoftonline.com (impone
    # Cross-Origin-Opener-Policy: same-origin, que corta window.opener de forma
    # permanente para esa ventana). Solo se usa en la rama SecureTokenDelivery=true.
    frontend_relay_url: str | None = None


class LocalAdSettings(BaseModel):
    server: str | None = None
    port: int = 389
    ldaps_port: int = 636
    base_dn: str | None = None
    service_account_dn: str | None = None
    service_account_password: str | None = Field(default=None, repr=False)
    service_account_password_file: Path | None = None
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    users_ou: str | None = None
    groups_ou: str | None = None
    netbios_domain: str | None = None
    funcionarios_activos_ou: str | None = None
    funcionarios_inactivos_ou: str | None = None
    estudiantes_activos_ou: str | None = None
    estudiantes_inactivos_ou: str | None = None


class PasswordChangeSettings(BaseModel):
    method: Literal["LocalAd", "AzureWriteback"] = "LocalAd"


class ProvisioningSettings(BaseModel):
    default_role_names: list[str] = Field(default_factory=lambda: ["R_EMPLOYEE"])
    grupo_funcionarios_activos_cn: str | None = None
    grupo_estudiantes_activos_cn: str | None = None
    student_employee_type_ids: list[int] = Field(default_factory=list)
    # Heredado de appsettings.Production.json del .NET: valor de prueba ("Zzprueba") nunca
    # confirmado para produccion. No resolver aqui, solo preservar el mismo pendiente.
    default_ad_group_id: str | None = None


class AppAuthSettings(BaseModel):
    client_roles: dict[str, list[str]] = Field(default_factory=dict)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
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

    jwt: JwtSettings = Field(default_factory=JwtSettings)
    cors: CorsSettings = Field(default_factory=CorsSettings)
    azure_ad: AzureAdSettings = Field(default_factory=AzureAdSettings)
    local_ad: LocalAdSettings = Field(default_factory=LocalAdSettings)
    password_change: PasswordChangeSettings = Field(default_factory=PasswordChangeSettings)
    provisioning: ProvisioningSettings = Field(default_factory=ProvisioningSettings)
    app_auth: AppAuthSettings = Field(default_factory=AppAuthSettings)

    @model_validator(mode="after")
    def load_and_validate_secrets(self) -> "Settings":
        is_production = self.app_env == "production"

        if self.database_url_file:
            self.database_url = _read_secret_file(
                self.database_url_file, production=is_production, label="DATABASE_URL_FILE"
            )
        if is_production and not self.database_url_file:
            raise ValueError("DATABASE_URL_FILE es obligatorio en production")

        # AzureAd y LocalAd todavia no tienen ningun router/servicio que los use (Fase 4),
        # por eso su ausencia no bloquea el arranque ni en production: solo se valida que,
        # si SE declara un archivo de secreto, sea legible.
        if self.azure_ad.client_secret_file:
            self.azure_ad.client_secret = _read_secret_file(
                self.azure_ad.client_secret_file,
                production=is_production,
                label="AZURE_AD__CLIENT_SECRET_FILE",
            )
        if self.local_ad.service_account_password_file:
            self.local_ad.service_account_password = _read_secret_file(
                self.local_ad.service_account_password_file,
                production=is_production,
                label="LOCAL_AD__SERVICE_ACCOUNT_PASSWORD_FILE",
            )

        return self

    @property
    def docs_enabled(self) -> bool:
        return self.app_env in {"development", "test", "validation"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
