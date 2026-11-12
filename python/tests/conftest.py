from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from repositoryuta.config import Settings, get_settings
from repositoryuta.core.rate_limit import limiter
from repositoryuta.core.security.jwt import get_rsa_key_provider
from repositoryuta.database import get_engine

# Import con efecto secundario: registra las tablas de estos modulos en
# Base.metadata antes de create_all() en el fixture sqlite_session.
from repositoryuta.models import (  # noqa: F401
    access_profile,
    app_param,
    application,
    audit,
    identity,
    notification,
    rbac,
    views,
    websocket,
)
from repositoryuta.models import session as session_models  # noqa: F401
from repositoryuta.models.base import Base
from repositoryuta.services import azure_auth_service
from repositoryuta.services.token_service import reset_lifetime_cache


@pytest.fixture(autouse=True)
def clear_settings_cache(monkeypatch: pytest.MonkeyPatch):
    # Ignora cualquier .env local del desarrollador (ej. python/.env para correr
    # el servidor real contra BD/Azure/AD real) — las pruebas deben ser
    # deterministas sin importar que exista ese archivo en el filesystem.
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_URL_FILE", raising=False)
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_rsa_key_provider.cache_clear()
    reset_lifetime_cache()
    limiter.reset()
    azure_auth_service.reset_caches()
    yield
    get_engine.cache_clear()
    get_settings.cache_clear()
    reset_lifetime_cache()
    get_rsa_key_provider.cache_clear()
    limiter.reset()
    azure_auth_service.reset_caches()


@pytest.fixture
def sqlite_session() -> Iterator[Session]:
    """SQLite en memoria para probar repositorios sin depender de SQL Server.

    `schema_translate_map` quita los prefijos "auth."/"dbo." (SQLite no los
    necesita — dbo es el esquema real de vw_UserRoles/vw_RoleMenuItems, ver
    models/views.py), y se registra SYSUTCDATETIME como funcion SQL propia
    para que los `server_default=text("SYSUTCDATETIME()")` de los modelos —
    copiados tal cual del .NET — funcionen igual aqui sin tocar los modelos.

    `StaticPool` + `check_same_thread=False`: los tests de routers ejecutan el
    endpoint en el threadpool de FastAPI (hilo distinto al del test), y
    `:memory:` de SQLite es por conexion — sin esto, la conexion creada en el
    hilo del test no es utilizable desde el hilo del endpoint.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        execution_options={"schema_translate_map": {"auth": None, "dbo": None}},
    )

    @event.listens_for(engine, "connect")
    def _register_sysutcdatetime(dbapi_connection, connection_record) -> None:
        dbapi_connection.create_function(
            "SYSUTCDATETIME", 0, lambda: datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
        )

    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture
def client(sqlite_session: Session) -> Iterator[TestClient]:
    """TestClient con get_db_session sobreescrito para usar sqlite_session en
    vez de intentar abrir una conexion real a SQL Server."""
    from repositoryuta.main import create_app
    from repositoryuta.routers.dependencies import get_db_session

    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: sqlite_session
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
