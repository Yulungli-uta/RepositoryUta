from datetime import datetime
from typing import ClassVar
from uuid import UUID, uuid4

from sqlalchemy import Boolean, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base

# NOTA: solo WebSocketConnection se modela aqui. WebSocketMessage y
# WebSocketStats existen como clases C# y DbSet<> en AuthDbContext, pero NO
# tienen ninguna IEntityTypeConfiguration ni entrada en OnModelCreating
# (verificado en Data/Configurations/_All.cs) — parecen entidades huerfanas
# sin mapeo real de tabla en el .NET actual. No se inventa un esquema para
# ellas; si de verdad se necesitan, hay que confirmar primero con quien
# administra la BD si la tabla existe y como se llama.


class WebSocketConnection(Base):
    """auth.tbl_WebSocketConnections. Bloqueado para consumo real hasta la
    decision de protocolo (regla de Fase 0 #13, SignalR sin equivalente nativo
    en FastAPI) — se modela la persistencia por completitud, sin repositorio
    ni schema todavia.
    """

    __tablename__ = "tbl_WebSocketConnections"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    id: Mapped[UUID] = mapped_column("Id", Uuid, primary_key=True, default=uuid4)
    application_id: Mapped[UUID] = mapped_column("ApplicationId", Uuid, nullable=False)
    connection_id: Mapped[str] = mapped_column("ConnectionId", Text, nullable=False)
    user_id: Mapped[UUID | None] = mapped_column("UserId", Uuid)
    browser_id: Mapped[str | None] = mapped_column("BrowserId", String(128))
    ip_address: Mapped[str | None] = mapped_column("IpAddress", String(64))
    user_agent: Mapped[str | None] = mapped_column("UserAgent", String(500))
    connected_at: Mapped[datetime] = mapped_column("ConnectedAt", default=datetime.now)
    last_ping_at: Mapped[datetime | None] = mapped_column("LastPingAt")
    disconnected_at: Mapped[datetime | None] = mapped_column("DisconnectedAt")
    is_active: Mapped[bool] = mapped_column("IsActive", Boolean, default=True)
