from typing import Any

from fastapi import APIRouter, Response

from repositoryuta.core.security.jwt import get_jwks

router = APIRouter(tags=["well-known"])


@router.get("/.well-known/jwks.json")
def get_jwks_endpoint(response: Response) -> dict[str, Any]:
    """Espejo de WellKnownController.GetJwks. Sin dependencia de Sesion/BD —
    solo lee la clave publica ya cacheada en memoria por get_rsa_key_provider.
    Cache-Control espejo de [ResponseCache(Duration=3600)] del .NET.
    """
    response.headers["Cache-Control"] = "public, max-age=3600"
    return get_jwks()
