using AutoMapper;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Models.DTOs;

namespace WsSeguUta.AuthSystem.API.Infrastructure.Mapping
{
  public class MappingProfile : Profile
  {
    public MappingProfile()
    {
      CreateMap<CreateUserDto, User>();
      CreateMap<UpdateUserDto, User>();

      CreateMap<CreateUserEmployeeDto, UserEmployee>();
      CreateMap<UpdateUserEmployeeDto, UserEmployee>();

      CreateMap<CreateAppParamDto, AppParam>();
      CreateMap<UpdateAppParamDto, AppParam>();

      CreateMap<CreateLocalCredentialDto, LocalUserCredential>();
      CreateMap<UpdateLocalCredentialDto, LocalUserCredential>();

      CreateMap<CreateSecurityTokenDto, SecurityToken>();
      CreateMap<UpdateSecurityTokenDto, SecurityToken>();

      CreateMap<CreatePasswordHistoryDto, PasswordHistory>();

      CreateMap<CreateUserAccountLockDto, UserAccountLock>();
      CreateMap<UpdateUserAccountLockDto, UserAccountLock>();

      CreateMap<CreateRoleDto, Role>();
      CreateMap<UpdateRoleDto, Role>();

      CreateMap<CreatePermissionDto, Permission>();
      CreateMap<UpdatePermissionDto, Permission>();

      CreateMap<CreateRolePermissionDto, RolePermission>();
      CreateMap<UpdateRolePermissionDto, RolePermission>();

      CreateMap<CreateUserRoleDto, UserRole>();
      CreateMap<UpdateUserRoleDto, UserRole>();

      CreateMap<CreateMenuItemDto, MenuItem>();
      CreateMap<UpdateMenuItemDto, MenuItem>();

      CreateMap<CreateRoleMenuItemDto, RoleMenuItem>();
      CreateMap<UpdateRoleMenuItemDto, RoleMenuItem>();

      CreateMap<CreateUserSessionDto, UserSession>();
      CreateMap<UpdateUserSessionDto, UserSession>();

      CreateMap<CreateFailedAttemptDto, FailedLoginAttempt>();
      CreateMap<UpdateFailedAttemptDto, FailedLoginAttempt>();

      CreateMap<CreateAuditLogDto, AuditLog>();
      CreateMap<UpdateAuditLogDto, AuditLog>();

      CreateMap<CreateLoginHistoryDto, LoginHistory>();
      CreateMap<UpdateLoginHistoryDto, LoginHistory>();

      CreateMap<CreateUserActivityLogDto, UserActivityLog>();
      CreateMap<UpdateUserActivityLogDto, UserActivityLog>();

      CreateMap<CreateRoleChangeHistoryDto, RoleChangeHistory>();
      CreateMap<UpdateRoleChangeHistoryDto, RoleChangeHistory>();

      CreateMap<CreatePermissionChangeHistoryDto, PermissionChangeHistory>();
      CreateMap<UpdatePermissionChangeHistoryDto, PermissionChangeHistory>();

      CreateMap<CreateAzureSyncLogDto, AzureSyncLog>();
      CreateMap<UpdateAzureSyncLogDto, AzureSyncLog>();
      CreateMap<CreateHRSyncLogDto, HRSyncLog>();
      CreateMap<UpdateHRSyncLogDto, HRSyncLog>();
    }
  }
}
