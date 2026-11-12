from typing import TYPE_CHECKING

from fastapi.openapi.utils import get_openapi

if TYPE_CHECKING:
    from fastapi import FastAPI

# Espejo de los [AllowAnonymous] reales del .NET (y de sus equivalentes ya
# documentados en cada router Python) — la unica fuente de verdad de "que
# requiere token" sigue siendo el Depends() real de cada endpoint
# (get_current_user_id/get_current_user_email/require_roles en
# routers/dependencies.py). Esta lista es SOLO para que Swagger dibuje el
# candado correcto; no participa en la validacion real. Si se agrega un
# endpoint nuevo sin ninguna de esas 3 dependencias, agregarlo aqui tambien
# (y confirmar que el motivo sea legitimo, no un olvido).
_PUBLIC_ENDPOINTS: set[tuple[str, str]] = {
    ("POST", "/api/app-auth/token"),
    ("POST", "/api/app-auth/legacy-login"),
    ("POST", "/api/app-auth/validate-token"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/refresh"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/validate-token"),
    ("GET", "/api/auth/password-change-method"),
    ("GET", "/api/auth/azure/url"),
    ("POST", "/api/auth/azure/url"),
    ("POST", "/api/auth/azure/exchange"),
    ("GET", "/api/auth/azure/callback"),
    ("POST", "/api/local-ad/authenticate"),
    ("POST", "/api/notifications/webhook-test"),
    ("GET", "/api/role-permissions/effective"),
    ("GET", "/api/roles/ping"),
    ("GET", "/.well-known/jwks.json"),
    # /healthz, /health/live, /health/ready tienen include_in_schema=False —
    # ni siquiera aparecen en el schema, no hace falta listarlos aqui.
}

_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


def install_bearer_auth_docs(app: "FastAPI") -> None:
    """Agrega el security scheme Bearer al OpenAPI para que /docs muestre el
    boton "Authorize" — cambio puramente de documentacion, no toca la
    validacion real de tokens (eso sigue viviendo en routers/dependencies.py).
    """

    def custom_openapi() -> dict:
        if app.openapi_schema:
            return app.openapi_schema

        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {})["BearerAuth"] = {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
        for path, operations in schema.get("paths", {}).items():
            for method, operation in operations.items():
                if method not in _HTTP_METHODS:
                    continue
                if (method.upper(), path) in _PUBLIC_ENDPOINTS:
                    continue
                operation["security"] = [{"BearerAuth": []}]

        app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = custom_openapi
