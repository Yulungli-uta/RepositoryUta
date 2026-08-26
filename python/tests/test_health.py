from fastapi.testclient import TestClient

from repositoryuta.main import create_app


def test_liveness_and_correlation_id() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/health/live", headers={"X-Correlation-ID": "test-123"})

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}
    assert response.headers["X-Correlation-ID"] == "test-123"


def test_readiness_is_unavailable_without_database() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
