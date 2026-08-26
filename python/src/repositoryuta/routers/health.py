from fastapi import APIRouter, Response, status

from repositoryuta.config import get_settings
from repositoryuta.database import database_is_ready

router = APIRouter(prefix="/health", tags=["health"])


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
