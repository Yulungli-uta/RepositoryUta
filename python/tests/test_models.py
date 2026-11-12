from repositoryuta.models.app_param import AppParam
from repositoryuta.models.identity import LocalUserCredential, User
from repositoryuta.models.rbac import MenuItem, Permission, Role, UserRole
from repositoryuta.models.session import UserSession


def test_tables_map_to_real_schema_and_names() -> None:
    assert User.__table__.schema == "auth"
    assert User.__table__.name == "tbl_Users"
    assert Role.__table__.name == "tbl_Roles"
    assert AppParam.__table__.name == "tbl_AppParams"
    assert UserSession.__table__.name == "tbl_UserSessions"


def test_app_param_primary_key_is_nemonic_not_an_id() -> None:
    pk_columns = [c.name for c in AppParam.__table__.primary_key.columns]
    assert pk_columns == ["Nemonic"]


def test_only_the_four_dotnet_isoftdeletable_models_expose_is_deleted_via_mixin() -> None:
    from repositoryuta.models.base import SoftDeleteMixin

    assert issubclass(User, SoftDeleteMixin)
    assert issubclass(Role, SoftDeleteMixin)
    assert issubclass(Permission, SoftDeleteMixin)
    assert issubclass(MenuItem, SoftDeleteMixin)
    # UserRole SI tiene columna is_deleted, pero a proposito no usa el mixin:
    # en .NET no implementa ISoftDeletable (sin filtro automatico alla tampoco).
    assert not issubclass(UserRole, SoftDeleteMixin)
    assert hasattr(UserRole, "is_deleted")


def test_local_user_credential_disables_implicit_returning_for_the_audit_trigger() -> None:
    assert LocalUserCredential.__table__.implicit_returning is False


def test_views_use_the_real_schema_per_view_not_all_auth() -> None:
    from repositoryuta.models.views import (
        VwActiveApiClient,
        VwActiveSession,
        VwRoleMenuItem,
        VwUserRole,
    )

    # vw_UserRoles y vw_RoleMenuItems viven en dbo, no en auth (unico caso
    # distinto en todo el esquema) — ver Models/Entities/Views.cs.
    assert VwUserRole.__table__.schema == "dbo"
    assert VwRoleMenuItem.__table__.schema == "dbo"
    assert VwActiveSession.__table__.schema == "auth"
    assert VwActiveApiClient.__table__.schema == "auth"


def test_access_profile_and_user_access_profile_are_not_soft_delete_mixin() -> None:
    from repositoryuta.models.access_profile import AccessProfile, UserAccessProfile
    from repositoryuta.models.base import SoftDeleteMixin

    # Tienen columna is_deleted pero, igual que UserRole, no implementan
    # ISoftDeletable en .NET (confirmado en _Entities.cs).
    assert not issubclass(AccessProfile, SoftDeleteMixin)
    assert not issubclass(UserAccessProfile, SoftDeleteMixin)
    assert hasattr(AccessProfile, "is_deleted")
    assert hasattr(UserAccessProfile, "is_deleted")


def test_legacy_auth_log_does_not_map_the_dotnet_only_authtype_field() -> None:
    from repositoryuta.models.application import LegacyAuthLog

    assert "AuthType" not in LegacyAuthLog.__table__.columns
