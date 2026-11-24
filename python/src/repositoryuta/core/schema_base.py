from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class ApiModel(BaseModel):
    """Base comun para todos los schemas que cruzan el limite HTTP.

    ASP.NET Core serializa por defecto en camelCase (AddControllers() sin
    configuracion de JSON que lo cambie, en Program.cs) — sin esto, esta API
    Python respondia en snake_case y rompia el contrato con cualquier cliente
    real (HrFrontend/HrBackend) que espere el formato de siempre.

    `populate_by_name=True` deja aceptar tambien el nombre de campo real
    (snake_case) al construir el modelo, ademas del alias camelCase — util
    para pruebas y para no ser mas estricto de lo necesario en la entrada.
    Para que la SALIDA sea camelCase de verdad hay que serializar con
    `by_alias=True` explicito (`model_dump(by_alias=True, mode="json")`).
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


def dump(model: BaseModel) -> dict:
    """Serializa un schema para salida HTTP: camelCase + tipos JSON-safe.

    Atajo de `model.model_dump(by_alias=True, mode="json")` — usarlo siempre
    para respuestas, nunca `.model_dump()` a secas (eso saldria en snake_case).
    """
    return model.model_dump(by_alias=True, mode="json")


def dump_json(model: BaseModel) -> str:
    """Version string de `dump()` — para guardar snapshots (ej. en AuditLog)."""
    return model.model_dump_json(by_alias=True)
