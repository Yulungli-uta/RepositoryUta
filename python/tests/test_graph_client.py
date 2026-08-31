import pytest

from repositoryuta.services import graph_client


class _FakeMsalApp:
    def __init__(self, token_result: dict) -> None:
        self._result = token_result

    def acquire_token_for_client(self, scopes):
        return self._result


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload or {}

    def raise_for_status(self) -> None:
        if not self.ok:
            raise Exception(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


@pytest.fixture(autouse=True)
def _reset() -> None:
    graph_client.reset_token_cache()
    yield
    graph_client.reset_token_cache()


def _patch_msal(monkeypatch: pytest.MonkeyPatch, token_result: dict | None = None) -> None:
    result = token_result or {"access_token": "tok", "expires_in": 3600}
    monkeypatch.setattr(
        graph_client.msal, "ConfidentialClientApplication", lambda *a, **k: _FakeMsalApp(result)
    )


def test_encode_path_segment_escapes_reserved_characters() -> None:
    assert graph_client.encode_path_segment("juan@uta.edu.ec") == "juan%40uta.edu.ec"
    assert graph_client.encode_path_segment("a/b") == "a%2Fb"
    assert graph_client.encode_path_segment("a?b#c") == "a%3Fb%23c"


def test_get_app_token_caches_between_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    class _CountingApp(_FakeMsalApp):
        def acquire_token_for_client(self, scopes):
            calls["count"] += 1
            return self._result

    monkeypatch.setattr(
        graph_client.msal,
        "ConfidentialClientApplication",
        lambda *a, **k: _CountingApp({"access_token": "tok", "expires_in": 3600}),
    )

    assert graph_client.get_app_token() == "tok"
    assert graph_client.get_app_token() == "tok"
    assert calls["count"] == 1


def test_get_app_token_raises_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_msal(monkeypatch, {"error": "invalid_client", "error_description": "bad secret"})

    with pytest.raises(RuntimeError, match="bad secret"):
        graph_client.get_app_token()


def test_graph_request_adds_bearer_token_and_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_msal(monkeypatch)
    captured = {}

    def _fake_request(method, url, headers=None, timeout=None, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        return _FakeResponse(200, {"ok": True})

    monkeypatch.setattr(graph_client.requests, "request", _fake_request)

    graph_client.graph_request("GET", "/users")

    assert captured["url"] == "https://graph.microsoft.com/v1.0/users"
    assert captured["headers"]["Authorization"] == "Bearer tok"


def test_graph_request_uses_absolute_url_for_next_link(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_msal(monkeypatch)
    captured = {}

    def _fake_request(method, url, headers=None, timeout=None, **kwargs):
        captured["url"] = url
        return _FakeResponse(200, {})

    monkeypatch.setattr(graph_client.requests, "request", _fake_request)

    graph_client.graph_request("GET", "https://graph.microsoft.com/v1.0/users?$skiptoken=abc")

    assert captured["url"] == "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
