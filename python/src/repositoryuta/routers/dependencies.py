from collections.abc import Callable, Iterator
from typing import Any
from uuid import UUID

from fastapi import Header, HTTPException, status
from sqlalchemy.orm import Session

from repositoryuta.core.security import jwt as jwt_core
from repositoryuta.database import get_session_factory


def get_db_session() -> Iterator[Session]:
    """Una Session por request — espejo del scope de AuthDbContext por request
    en .NET (AddDbContext es Scoped por defecto). FastAPI cachea el resultado
    de esta dependencia dentro de un mismo request, asi que declararla en
    varios routers/dependencias del mismo endpoint reutiliza la misma Session,
    no abre una por cada Depends().
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


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="No autorizado")
    return authorization[len("Bearer ") :].strip()


def _decode_bearer_payload(authorization: str | None) -> dict[str, Any]:
    """Espejo del middleware AddJwtBearer de .NET que respalda [Authorize]:
    solo valida firma/issuer/audience/expiracion — cero consultas a BD."""
    token = _extract_bearer_token(authorization)
    try:
        return jwt_core.decode_token(token)
    except Exception as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from exc


def _user_id_from_payload(payload: dict[str, Any]) -> UUID:
    raw_id = payload.get(jwt_core.CLAIM_NAME_IDENTIFIER) or payload.get("sub")
    try:
        return UUID(str(raw_id))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from exc


def get_current_user_id(authorization: str | None = Header(default=None)) -> UUID:
    """Espejo de [Authorize] (sin roles): cualquier usuario autenticado."""
    payload = _decode_bearer_payload(authorization)
    return _user_id_from_payload(payload)


def get_current_user_email(authorization: str | None = Header(default=None)) -> str:
    """Espejo de GetCurrentUserEmail() (varios controllers): claim "email" del
    token, o "system" si no viene (ej. token de aplicacion)."""
    payload = _decode_bearer_payload(authorization)
    return payload.get("email") or "system"


def require_roles(*roles: str) -> Callable[..., UUID]:
    """Espejo de [Authorize(Roles="A,B")]: exige que el claim role del token
    incluya alguno de los roles dados."""

    def _dependency(authorization: str | None = Header(default=None)) -> UUID:
        payload = _decode_bearer_payload(authorization)
        user_roles = set(jwt_core.roles_from_payload(payload))
        if not user_roles.intersection(roles):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, detail="No tiene permisos suficientes"
            )
        return _user_id_from_payload(payload)

    return _dependency
