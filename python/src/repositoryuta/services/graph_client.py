import logging
from typing import Any
from urllib.parse import quote

import msal
import requests

from repositoryuta.config import get_settings
from repositoryuta.core.ttl_cache import TtlCache

logger = logging.getLogger(__name__)

# Cliente Graph compartido — espejo del GraphServiceClient unico que .NET
# inyecta en AzureManagementService/MicrosoftLicenseService. Decision de
# arquitectura (ver [[repositoryuta-python-migration-architecture-rules]]):
# NO se usa msgraph-sdk (falla instalar en Windows por longitud de path);
# msal (token app-only) + requests (REST directo) — mismo patron que el
# propio .NET usa para su unica llamada a Graph fuera del SDK (AzureAuthService./me).

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]
_TOKEN_CACHE_MARGIN_SECONDS = 300

_token_cache = TtlCache()


def reset_token_cache() -> None:
    """Solo para pruebas."""
    _token_cache.clear()


def get_app_token() -> str:
    """Token app-only (client credentials), cacheado en memoria."""
    cached = _token_cache.get("graph_app_token")
    if cached is not None:
        return cached

    settings = get_settings().azure_ad
    app = msal.ConfidentialClientApplication(
        settings.client_id,
        client_credential=settings.client_secret,
        authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
    )
    result = app.acquire_token_for_client(scopes=_GRAPH_SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            result.get("error_description") or "No se pudo obtener token de Microsoft Graph."
        )

    expires_in = int(result.get("expires_in", 3600))
    ttl = max(expires_in - _TOKEN_CACHE_MARGIN_SECONDS, 60)
    _token_cache.set("graph_app_token", result["access_token"], ttl)
    return result["access_token"]


def encode_path_segment(value: str) -> str:
    """Escapa un valor (upn, objectId, groupId, roleId...) para usarlo como
    segmento de path en una URL de Graph.

    Los generadores fluent del SDK .NET (`_graph.Users[upn]`) escapan esto
    automaticamente; aqui se arma la URL a mano con f-strings (ver decision de
    arquitectura en el modulo), asi que hay que hacerlo explicito. Sin esto,
    un UPN con '/', '?', '#' etc. (via un endpoint sin restriccion de rol,
    como /api/licenses/*) podria alterar la ruta real enviada a Graph."""
    return quote(str(value), safe="")


def graph_request(method: str, path: str, **kwargs: Any) -> requests.Response:
    """path puede ser una ruta relativa ('/users') o una nextLink absoluta
    (empieza con https://) — igual que WithUrl()/RequestAdapter.SendAsync
    del .NET para paginacion."""
    token = get_app_token()
    headers = kwargs.pop("headers", {})
    headers["Authorization"] = f"Bearer {token}"
    url = path if path.startswith("http") else f"{GRAPH_BASE_URL}{path}"
    return requests.request(method, url, headers=headers, timeout=15, **kwargs)
