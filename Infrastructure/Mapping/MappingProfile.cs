using Mapster;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Mapping
{
  public class MappingProfile : IRegister
  {
    public void Register(TypeAdapterConfig config)
    {
      config.NewConfig<CreateUserDto, User>();
      // Ignorar campos null al actualizar User para evitar pisar valores existentes (e.g. UserType NOT NULL)
      config.NewConfig<UpdateUserDto, User>()
        .IgnoreNullValues(true);

      config.NewConfig<CreateUserEmployeeDto, UserEmployee>();
      config.NewConfig<UpdateUserEmployeeDto, UserEmployee>();

      config.NewConfig<CreateAppParamDto, AppParam>();
      config.NewConfig<UpdateAppParamDto, AppParam>();

      config.NewConfig<CreateLocalCredentialDto, LocalUserCredential>();
      config.NewConfig<UpdateLocalCredentialDto, LocalUserCredential>();

      config.NewConfig<CreateSecurityTokenDto, SecurityToken>();
      config.NewConfig<UpdateSecurityTokenDto, SecurityToken>();

      config.NewConfig<CreatePasswordHistoryDto, PasswordHistory>();

      config.NewConfig<CreateUserAccountLockDto, UserAccountLock>();
      config.NewConfig<UpdateUserAccountLockDto, UserAccountLock>();

      config.NewConfig<CreateRoleDto, Role>();
      config.NewConfig<UpdateRoleDto, Role>();

      config.NewConfig<CreatePermissionDto, Permission>();
      config.NewConfig<UpdatePermissionDto, Permission>();

      config.NewConfig<CreateRolePermissionDto, RolePermission>();
      config.NewConfig<UpdateRolePermissionDto, RolePermission>();

      config.NewConfig<CreateUserRoleDto, UserRole>();
      config.NewConfig<UpdateUserRoleDto, UserRole>();

      config.NewConfig<CreateMenuItemDto, MenuItem>();
      config.NewConfig<UpdateMenuItemDto, MenuItem>();

      config.NewConfig<CreateRoleMenuItemDto, RoleMenuItem>();
      config.NewConfig<UpdateRoleMenuItemDto, RoleMenuItem>();

      config.NewConfig<CreateUserSessionDto, UserSession>();
      config.NewConfig<UpdateUserSessionDto, UserSession>();

      config.NewConfig<CreateFailedAttemptDto, FailedLoginAttempt>();
      config.NewConfig<UpdateFailedAttemptDto, FailedLoginAttempt>();

      config.NewConfig<CreateAuditLogDto, AuditLog>();
      config.NewConfig<UpdateAuditLogDto, AuditLog>();

      config.NewConfig<CreateLoginHistoryDto, LoginHistory>();
      config.NewConfig<UpdateLoginHistoryDto, LoginHistory>();

      config.NewConfig<CreateUserActivityLogDto, UserActivityLog>();
      config.NewConfig<UpdateUserActivityLogDto, UserActivityLog>();

      config.NewConfig<CreateRoleChangeHistoryDto, RoleChangeHistory>();
      config.NewConfig<UpdateRoleChangeHistoryDto, RoleChangeHistory>();

      config.NewConfig<CreatePermissionChangeHistoryDto, PermissionChangeHistory>();
      config.NewConfig<UpdatePermissionChangeHistoryDto, PermissionChangeHistory>();

      config.NewConfig<CreateAzureSyncLogDto, AzureSyncLog>();
      config.NewConfig<UpdateAzureSyncLogDto, AzureSyncLog>();
      config.NewConfig<CreateHRSyncLogDto, HRSyncLog>();
      config.NewConfig<UpdateHRSyncLogDto, HRSyncLog>();

      config.NewConfig<CreateAccessProfileDto, AccessProfile>();
      config.NewConfig<UpdateAccessProfileDto, AccessProfile>()
        .IgnoreNullValues(true);

      config.NewConfig<CreateAccessProfileRoleDto, AccessProfileRole>();
      config.NewConfig<UpdateAccessProfileRoleDto, AccessProfileRole>();
    }
  }
}
