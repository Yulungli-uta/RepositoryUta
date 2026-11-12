from datetime import UTC, datetime
from unittest.mock import patch

from repositoryuta.core import clock


def _fake_now(utc_moment: datetime):
    def _now(tz=None):
        return utc_moment.astimezone(tz) if tz else utc_moment.replace(tzinfo=None)

    return _now


def test_now_is_naive_ecuador_time() -> None:
    value = clock.now()
    assert value.tzinfo is None
    diff = abs((datetime.now(UTC).replace(tzinfo=None) - value).total_seconds() - 5 * 3600)
    assert diff < 5


def test_today_uses_ecuador_day_after_19h() -> None:
    # 00:30 UTC del 27 = 19:30 del 26 en Ecuador: "hoy" sigue siendo el 26
    moment = datetime(2026, 10, 27, 0, 30, tzinfo=UTC)
    with patch("repositoryuta.core.clock.datetime") as fake:
        fake.now.side_effect = _fake_now(moment)
        assert clock.now() == datetime(2026, 10, 26, 19, 30)
        assert clock.today().isoformat() == "2026-10-26"


def test_utc_now_has_utc_tzinfo() -> None:
    assert clock.utc_now().tzinfo is UTC
