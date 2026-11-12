from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

import pyodbc
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from repositoryuta.config import get_settings

# SQLAlchemy administra el pool. Desactivar el pool global de pyodbc evita
# retener un segundo conjunto de conexiones fuera del control de la app.
pyodbc.pooling = False


@lru_cache(maxsize=1)
def get_engine() -> Engine | None:
    settings = get_settings()
    if not settings.database_url:
        return None
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        pool_recycle=settings.db_pool_recycle_seconds,
    )


def database_is_ready() -> bool:
    engine = get_engine()
    if engine is None:
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def dispose_engine() -> None:
    engine = get_engine()
    if engine is not None:
        engine.dispose()


def get_session_factory() -> sessionmaker[Session]:
    engine = get_engine()
    if engine is None:
        raise RuntimeError("No hay motor de base de datos configurado (DATABASE_URL_FILE).")
    return sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Una transaccion por unidad de trabajo: commit si todo sale bien, rollback
    si no. Los repositorios reciben la Session ya abierta — nunca crean la suya,
    ni hacen commit ellos mismos (eso es responsabilidad de quien orquesta la
    unidad de trabajo, tipicamente un servicio de Fase 4).
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
