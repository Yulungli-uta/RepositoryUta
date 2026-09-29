from sqlalchemy import BigInteger, Boolean, Integer, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# SQLite no autoincrementa una PK BIGINT (solo su alias de rowid, que exige el
# tipo literal "INTEGER"). BIGINT sigue siendo el tipo real en SQL Server;
# esto solo cambia que tipo se manda en la sesion de pruebas contra SQLite.
BigIntegerPk = BigInteger().with_variant(Integer(), "sqlite")


class SoftDeleteMixin:
    """Solo para los 4 modelos que en .NET implementan ISoftDeletable
    (User, Role, Permission, MenuItem — ver AuthDbContext.cs OnModelCreating).

    No agregar a otras entidades con columna IsDeleted (Application, AccessProfile,
    UserAccessProfile, UserRole): en .NET esas NO tienen el filtro automatico de
    soft-delete, y cada repositorio debe decidir su propio filtrado manual para
    ellas (regla de Fase 0). Este mixin tampoco aplica ningun filtro por si solo
    — cada repositorio de estos 4 modelos debe agregar `.where(is_deleted=False)`
    explicitamente en sus metodos de lectura (a proposito, sin "magia" global que
    pueda terminar aplicandose a una entidad que en .NET no la tiene).
    """

    # "IsDeleted" explicito: a diferencia de SQLite (case-insensitive), la BD real
    # usa collation case-sensitive — sin el nombre exacto, SQL Server responde
    # "Invalid column name 'is_deleted'" porque no existe esa columna en minusculas.
    is_deleted: Mapped[bool] = mapped_column(
        "IsDeleted", Boolean, default=False, server_default=text("0")
    )
