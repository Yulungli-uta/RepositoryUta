from unittest.mock import patch

from fastapi.testclient import TestClient

from repositoryuta.main import create_app


def test_request_logging_middleware_logs_expected_fields() -> None:
    with (
        patch("repositoryuta.middleware.logger") as mock_logger,
        TestClient(create_app()) as client,
    ):
        response = client.get("/health/live")

    assert response.status_code == 200
    mock_logger.info.assert_called_once()
    _, kwargs = mock_logger.info.call_args
    extra = kwargs["extra"]
    assert extra["method"] == "GET"
    assert extra["path"] == "/health/live"
    assert extra["status_code"] == 200
    assert extra["correlation_id"] is not None
    assert "duration_ms" in extra
