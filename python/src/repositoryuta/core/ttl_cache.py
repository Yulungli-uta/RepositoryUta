import threading
import time
from typing import Any


class TtlCache:
    """Espejo minimo de IMemoryCache (Set/TryGetValue/Remove con TTL) — solo lo
    que AzureAuthService.cs necesita para el estado OAuth y el deliveryCode
    PKCE. En memoria del proceso, igual que IMemoryCache real (no sobrevive un
    reinicio ni se comparte entre instancias)."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()

    def set(self, key: str, value: Any, ttl_seconds: float) -> None:
        with self._lock:
            self._store[key] = (value, time.monotonic() + ttl_seconds)

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() >= expires_at:
                del self._store[key]
                return None
            return value

    def remove(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        """Solo para pruebas."""
        with self._lock:
            self._store.clear()
