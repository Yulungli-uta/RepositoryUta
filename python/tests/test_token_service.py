import hashlib

from repositoryuta.models.app_param import AppParam
from repositoryuta.services.token_service import (
    get_access_token_lifetime_minutes,
    hash_token,
    reset_lifetime_cache,
)


def test_falls_back_to_settings_when_param_is_missing(sqlite_session) -> None:
    assert get_access_token_lifetime_minutes(sqlite_session) == 30


def test_reads_the_value_from_app_params(sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="Jwt:AccessTokenLifetimeMinutes", value="45"))
    sqlite_session.flush()

    assert get_access_token_lifetime_minutes(sqlite_session) == 45


def test_falls_back_when_value_is_not_a_valid_integer(sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="Jwt:AccessTokenLifetimeMinutes", value="not-a-number"))
    sqlite_session.flush()

    assert get_access_token_lifetime_minutes(sqlite_session) == 30


def test_result_is_cached_until_reset(sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="Jwt:AccessTokenLifetimeMinutes", value="45"))
    sqlite_session.flush()

    assert get_access_token_lifetime_minutes(sqlite_session) == 45

    # Cambiar el valor en BD no debe verse hasta que expire/limpie el cache.
    param = sqlite_session.get(AppParam, "Jwt:AccessTokenLifetimeMinutes")
    param.value = "60"
    sqlite_session.flush()
    assert get_access_token_lifetime_minutes(sqlite_session) == 45

    reset_lifetime_cache()
    assert get_access_token_lifetime_minutes(sqlite_session) == 60


def test_hash_token_matches_dotnet_uppercase_sha256() -> None:
    expected = hashlib.sha256(b"my-refresh-token").hexdigest().upper()

    assert hash_token("my-refresh-token") == expected
    assert hash_token("my-refresh-token") == hash_token("my-refresh-token")
