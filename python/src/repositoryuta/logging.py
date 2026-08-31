import json
import logging
from datetime import UTC, datetime

# Campos que la capa de auditoria/logging de requests (middleware.py) adjunta via
# `extra=`. "user" queda sin usar hasta que haya autenticacion wireada (Fase 5);
# se ignora en silencio mientras tanto porque simplemente no llega en el record.
_EXTRA_FIELDS = (
    "correlation_id",
    "client_ip",
    "method",
    "path",
    "status_code",
    "duration_ms",
    "user",
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level.upper())
