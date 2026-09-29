from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from repositoryuta.core.schema_base import ApiModel


class ApiResponse(ApiModel):
    """Espejo del record ApiResponse (Models/DTOs/_Dtos.cs) usado en todo el .NET."""

    success: bool
    data: Any | None = None
    message: str | None = None
    errors: list[str] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def ok(cls, data: Any | None = None, message: str | None = None) -> "ApiResponse":
        return cls(success=True, data=data, message=message)

    @classmethod
    def fail(cls, message: str, errors: list[str] | None = None) -> "ApiResponse":
        return cls(success=False, message=message, errors=errors)
