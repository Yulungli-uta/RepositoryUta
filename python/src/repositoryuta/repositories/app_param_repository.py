from sqlalchemy import select
from sqlalchemy.orm import Session

from repositoryuta.models.app_param import AppParam


class AppParamRepository:
    """Acceso a auth.tbl_AppParams. La orquestacion de cache (IMemoryCache en
    JwtTokenService.GetAccessTokenLifetimeAsync) es logica de negocio y
    pertenece a services/ en Fase 4 — aqui solo la consulta pura.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, nemonic: str) -> AppParam | None:
        return self._session.get(AppParam, nemonic)

    def get_value(self, nemonic: str) -> str | None:
        return self._session.scalar(select(AppParam.value).where(AppParam.nemonic == nemonic))
