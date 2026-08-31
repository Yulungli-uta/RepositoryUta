from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from repositoryuta.config import get_settings
from repositoryuta.core.exceptions import register_exception_handlers
from repositoryuta.core.openapi_security import install_bearer_auth_docs
from repositoryuta.core.rate_limit import limiter
from repositoryuta.database import dispose_engine
from repositoryuta.logging import configure_logging
from repositoryuta.middleware import (
    CorrelationIdMiddleware,
    RequestLoggingMiddleware,
    UnhandledExceptionMiddleware,
)
from repositoryuta.routers.access_profile_roles import router as access_profile_roles_router
from repositoryuta.routers.access_profiles import router as access_profiles_router
from repositoryuta.routers.app_auth import router as app_auth_router
from repositoryuta.routers.app_params import router as app_params_router
from repositoryuta.routers.audit_log import router as audit_log_router
from repositoryuta.routers.auth import router as auth_router
from repositoryuta.routers.azure_management import router as azure_management_router
from repositoryuta.routers.azure_sync_log import router as azure_sync_log_router
from repositoryuta.routers.failed_logins import router as failed_logins_router
from repositoryuta.routers.health import root_router as health_root_router
from repositoryuta.routers.health import router as health_router
from repositoryuta.routers.hr_sync_log import router as hr_sync_log_router
from repositoryuta.routers.license import router as license_router
from repositoryuta.routers.local_ad import router as local_ad_router
from repositoryuta.routers.local_credentials import router as local_credentials_router
from repositoryuta.routers.login_history import router as login_history_router
from repositoryuta.routers.menu import router as menu_router
from repositoryuta.routers.menu_items import router as menu_items_router
from repositoryuta.routers.notification import router as notification_router
from repositoryuta.routers.permission_change_history import (
    router as permission_change_history_router,
)
from repositoryuta.routers.permissions import router as permissions_router
from repositoryuta.routers.provisioning import router as provisioning_router
from repositoryuta.routers.role_change_history import router as role_change_history_router
from repositoryuta.routers.role_menu_items import router as role_menu_items_router
from repositoryuta.routers.role_permissions import router as role_permissions_router
from repositoryuta.routers.roles import router as roles_router
from repositoryuta.routers.security_tokens import router as security_tokens_router
from repositoryuta.routers.session_management import router as session_management_router
from repositoryuta.routers.sessions import router as sessions_router
from repositoryuta.routers.student_provisioning import router as student_provisioning_router
from repositoryuta.routers.user_access_profiles import router as user_access_profiles_router
from repositoryuta.routers.user_activity import router as user_activity_router
from repositoryuta.routers.user_employees import router as user_employees_router
from repositoryuta.routers.user_roles import router as user_roles_router
from repositoryuta.routers.users import router as users_router
from repositoryuta.routers.well_known import router as well_known_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        root_path=settings.root_path,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    if settings.docs_enabled:
        install_bearer_auth_docs(app)

    # Orden (el ultimo add_middleware es el MAS externo, se ejecuta primero):
    # CORS > CorrelationId > UnhandledException > RequestLogging > router.
    # RequestLogging necesita request.state.correlation_id ya seteado al loggear;
    # UnhandledException necesita quedar DENTRO de CORS (ver middleware.py) para
    # que un 500 no controlado si lleve headers CORS.
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(UnhandledExceptionMiddleware)
    app.add_middleware(CorrelationIdMiddleware)

    # Espejo de AddCors()/UseCors() en Program.cs. Debe quedar como el middleware
    # MAS externo (agregado al final) para que CORSMiddleware intercepte los
    # preflight OPTIONS antes que cualquier otra cosa (rate limit, auth, etc.).
    # Los origins (incluidos los de desarrollo) se configuran enteramente por
    # env var (CORS__ORIGINS en .env) — nada hardcodeado aca, a diferencia del
    # .NET real que sí hardcodea los origins de desarrollo en Program.cs.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors.origins,
        allow_credentials=settings.cors.allow_credentials,
        allow_methods=settings.cors.allowed_methods or ["*"],
        allow_headers=settings.cors.allowed_headers or ["*"],
        max_age=settings.cors.preflight_max_age_seconds,
    )

    register_exception_handlers(app)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    app.include_router(health_router)
    app.include_router(health_root_router)
    app.include_router(well_known_router)
    app.include_router(auth_router)
    app.include_router(menu_router)
    app.include_router(users_router)
    app.include_router(roles_router)
    app.include_router(permissions_router)
    app.include_router(role_menu_items_router)
    app.include_router(user_roles_router)
    app.include_router(access_profiles_router)
    app.include_router(access_profile_roles_router)
    app.include_router(user_access_profiles_router)
    app.include_router(session_management_router)
    app.include_router(audit_log_router)
    app.include_router(login_history_router)
    app.include_router(failed_logins_router)
    app.include_router(app_params_router)
    app.include_router(security_tokens_router)
    app.include_router(sessions_router)
    app.include_router(menu_items_router)
    app.include_router(role_permissions_router)
    app.include_router(role_change_history_router)
    app.include_router(permission_change_history_router)
    app.include_router(user_activity_router)
    app.include_router(azure_sync_log_router)
    app.include_router(hr_sync_log_router)
    app.include_router(local_credentials_router)
    app.include_router(user_employees_router)
    app.include_router(app_auth_router)
    app.include_router(local_ad_router)
    app.include_router(azure_management_router)
    app.include_router(license_router)
    app.include_router(provisioning_router)
    app.include_router(student_provisioning_router)
    app.include_router(notification_router)
    return app


app = create_app()
