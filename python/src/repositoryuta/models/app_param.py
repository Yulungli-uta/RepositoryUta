from datetime import datetime
from typing import ClassVar

from sqlalchemy import Boolean, String, text
from sqlalchemy.orm import Mapped, mapped_column

from repositoryuta.models.base import Base


class AppParam(Base):
    """auth.tbl_AppParams. La PK es Nemonic (string), no un id autogenerado.

    Incluye el parametro "Jwt:AccessTokenLifetimeMinutes" que lee TokenService
    en caliente (regla de Fase 0 #4) — ver core/security/jwt.py y, cuando exista,
    repositories/app_param_repository.py.
    """

    __tablename__ = "tbl_AppParams"
    __table_args__: ClassVar[dict[str, object]] = {"schema": "auth"}

    nemonic: Mapped[str] = mapped_column("Nemonic", String(100), primary_key=True)
    value: Mapped[str] = mapped_column("Value", String(4000), nullable=False)
    data_type: Mapped[str] = mapped_column(
        "DataType", String(50), default="string", server_default="string"
    )
    category: Mapped[str] = mapped_column(
        "Category", String(100), default="General", server_default="General"
    )
    description: Mapped[str | None] = mapped_column("Description", String(300))
    is_encrypted: Mapped[bool] = mapped_column(
        "IsEncrypted", Boolean, default=False, server_default=text("0")
    )
    last_modified: Mapped[datetime] = mapped_column(
        "LastModified", server_default=text("SYSUTCDATETIME()")
    )
    modified_by: Mapped[str | None] = mapped_column("ModifiedBy", String(320))
