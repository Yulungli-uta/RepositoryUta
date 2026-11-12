import json
import logging

from repositoryuta.logging import JsonFormatter


def test_json_formatter_includes_known_extra_fields() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="repositoryuta.requests",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="GET /health/live -> 200",
        args=(),
        exc_info=None,
    )
    record.correlation_id = "abc-123"
    record.status_code = 200

    payload = json.loads(formatter.format(record))

    assert payload["correlation_id"] == "abc-123"
    assert payload["status_code"] == 200
    assert "user" not in payload
