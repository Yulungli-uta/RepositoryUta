from fastapi import FastAPI
from fastapi.testclient import TestClient

from repositoryuta.core.exceptions import (
    DirectoryServiceError,
    NotFoundError,
    register_exception_handlers,
)
from repositoryuta.middleware import CorrelationIdMiddleware, UnhandledExceptionMiddleware


def _build_test_app() -> FastAPI:
    app = FastAPI()
    # UnhandledExceptionMiddleware debe quedar dentro de CorrelationIdMiddleware
    # (agregado antes) para que request.state.correlation_id ya exista al
    # construir el body del 500 — mismo orden que create_app() en main.py.
    app.add_middleware(UnhandledExceptionMiddleware)
    app.add_middleware(CorrelationIdMiddleware)
    register_exception_handlers(app)

    @app.get("/boom-domain")
    def boom_domain() -> None:
        raise NotFoundError("Usuario no encontrado")

    @app.get("/boom-unhandled")
    def boom_unhandled() -> None:
        raise RuntimeError("detalle interno sensible: password=hunter2")

    return app


def test_domain_error_returns_its_status_and_message() -> None:
    with TestClient(_build_test_app(), raise_server_exceptions=False) as client:
        response = client.get("/boom-domain")

    assert response.status_code == 404
    body = response.json()
    assert body["error"] == "Usuario no encontrado"
    assert "correlation_id" in body


def test_unhandled_exception_never_leaks_raw_message() -> None:
    with TestClient(_build_test_app(), raise_server_exceptions=False) as client:
        response = client.get("/boom-unhandled")

    assert response.status_code == 500
    assert response.json()["error"] == "Error interno del servidor"
    assert "hunter2" not in response.text


def test_directory_service_error_has_fixed_safe_message() -> None:
    assert DirectoryServiceError().message == "Error de configuración de Active Directory"
