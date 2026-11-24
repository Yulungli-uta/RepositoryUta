import logging
import time
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from repositoryuta.core.exceptions import error_body

logger = logging.getLogger("repositoryuta.requests")
error_logger = logging.getLogger("repositoryuta.errors")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response


class UnhandledExceptionMiddleware(BaseHTTPMiddleware):
    """Reemplaza a @app.exception_handler(Exception) — ver el comentario en
    core/exceptions.py::register_exception_handlers sobre por que ese handler
    dejaba los 500 sin headers CORS. DomainError sigue manejado normalmente
    por Starlette (ExceptionMiddleware, mas interno que este middleware) — este
    try/except solo atrapa lo que ninguno de esos dos ya resolvio.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
        except Exception:
            # Nunca se expone str(exc) al cliente: puede filtrar detalle de
            # infraestructura o, en flujos de auth, el motivo exacto de un
            # fallo (no-negociable del ecosistema).
            correlation_id = getattr(request.state, "correlation_id", None)
            error_logger.exception(
                "Error no controlado", extra={"correlation_id": correlation_id}
            )
            return JSONResponse(
                status_code=500, content=error_body("Error interno del servidor", request)
            )


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Trazabilidad HTTP estructurada, equivalente a UseSerilogRequestLogging().

    No es el AuditService de negocio (escritura real en auth.tbl_AuditLog): ese
    necesita repositorio y un usuario autenticado, y llega en Fase 4. Aqui solo
    se registra lo que ya esta disponible a nivel de transporte.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        started_at = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)

        logger.info(
            "%s %s -> %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "correlation_id": getattr(request.state, "correlation_id", None),
                "client_ip": request.client.host if request.client else None,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response
