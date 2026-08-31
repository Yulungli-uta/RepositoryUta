import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class DomainError(Exception):
    """Base para errores de negocio con un mensaje seguro para el cliente."""

    status_code = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(DomainError):
    status_code = 404


class ConflictError(DomainError):
    status_code = 409


class BusinessValidationError(DomainError):
    status_code = 422


class DirectoryServiceError(DomainError):
    """Espejo de LdapException/DirectoryOperationException del .NET.

    Mismo mensaje seguro que ErrorHandlerMiddleware.cs: da una pista accionable
    sin filtrar el detalle real de LDAP/Active Directory.
    """

    status_code = 502

    def __init__(self) -> None:
        super().__init__("Error de configuración de Active Directory")


def error_body(message: str, request: Request) -> dict[str, str | None]:
    return {
        "error": message,
        "correlation_id": getattr(request.state, "correlation_id", None),
    }


def register_exception_handlers(app: FastAPI) -> None:
    """Solo DomainError se registra aca. El catch-all de excepciones NO
    controladas vive en middleware.py::UnhandledExceptionMiddleware — un
    handler registrado para la clase Exception "pura" via
    @app.exception_handler(Exception) lo enruta Starlette a
    ServerErrorMiddleware (el mas externo, por ENCIMA de CORSMiddleware), asi
    que esa respuesta nunca lleva headers CORS y el navegador reporta
    "bloqueado por CORS" en vez del 500 real. Como middleware normal (agregado
    dentro de CORSMiddleware) la respuesta si los lleva."""

    @app.exception_handler(DomainError)
    async def _domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=error_body(exc.message, request))
