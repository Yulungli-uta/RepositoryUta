from fastapi import APIRouter, Response, status
from fastapi.responses import PlainTextResponse

from repositoryuta.config import get_settings
from repositoryuta.database import database_is_ready

router = APIRouter(prefix="/health", tags=["health"])

# Espejo de Program.cs: AddHealthChecks().AddDbContextCheck<AuthDbContext>() +
# MapHealthChecks("/healthz") — path exacto en la raiz (no bajo /health), sin
# writer personalizado en el .NET real, por eso el body es texto plano
# "Healthy"/"Unhealthy", no JSON. Separado de /health/live y /health/ready
# (que no existen en el .NET — son una adicion propia de esta migracion para
# probes de contenedor mas granulares) para no romper ningun consumidor que
# ya dependa del contrato original de /healthz.
root_router = APIRouter(tags=["health"])


@root_router.get("/healthz", include_in_schema=False)
def healthz() -> PlainTextResponse:
    if database_is_ready():
        return PlainTextResponse("Healthy")
    return PlainTextResponse("Unhealthy", status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


@router.get("/live", include_in_schema=False)
def live() -> dict[str, str]:
    return {"status": "healthy"}


@router.get("/ready", include_in_schema=False)
def ready(response: Response) -> dict[str, str]:
    settings = get_settings()
    if settings.app_env == "validation" and not settings.database_url:
        return {"status": "ready", "mode": "validation"}
    if not database_is_ready():
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready"}
    return {"status": "ready"}
