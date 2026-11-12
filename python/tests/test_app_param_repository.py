from repositoryuta.models.app_param import AppParam
from repositoryuta.repositories.app_param_repository import AppParamRepository


def test_get_value_returns_none_when_missing(sqlite_session) -> None:
    assert AppParamRepository(sqlite_session).get_value("Jwt:AccessTokenLifetimeMinutes") is None


def test_get_value_returns_the_stored_value(sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="Jwt:AccessTokenLifetimeMinutes", value="45"))
    sqlite_session.flush()

    assert (
        AppParamRepository(sqlite_session).get_value("Jwt:AccessTokenLifetimeMinutes") == "45"
    )


def test_get_returns_the_full_row(sqlite_session) -> None:
    sqlite_session.add(AppParam(nemonic="PasswordPolicy.MinLength", value="8"))
    sqlite_session.flush()

    param = AppParamRepository(sqlite_session).get("PasswordPolicy.MinLength")

    assert param is not None
    assert param.value == "8"
