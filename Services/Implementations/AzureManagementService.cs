using Azure.Identity;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using GraphUser = Microsoft.Graph.Models.User;
using GraphGroup = Microsoft.Graph.Models.Group;
using LocalUser = WsSeguUta.AuthSystem.API.Models.Entities.User;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public class AzureManagementService : IAzureManagementService
{
    private readonly GraphServiceClient _graphClient;
    private readonly IAzureAdRepository _azureAdRepo;
    private readonly AuthDbContext _context;
    private readonly ILogger<AzureManagementService> _logger;

    public AzureManagementService(
        GraphServiceClient graphClient,
        IAzureAdRepository azureAdRepo,
        AuthDbContext context,
        ILogger<AzureManagementService> logger)
    {
        _graphClient = graphClient;
        _azureAdRepo = azureAdRepo;
        _context = context;
        _logger = logger;
    }

    // ========== GESTIÓN DE USUARIOS ==========

    public async Task<AzureUserDto> CreateUserInAzureAsync(CreateAzureUserDto dto)
    {
        try
        {
            _logger.LogInformation($"Creando usuario en Azure AD: {dto.Email}");

            // Validar email
            if (!IsValidEmail(dto.Email))
                throw new ArgumentException("Email inválido");

            // Validar contraseña
            var passwordValidation = await ValidatePasswordPolicyAsync(dto.Password);
            if (!passwordValidation.IsValid)
                throw new ArgumentException($"Contraseña no cumple con la política: {string.Join(", ", passwordValidation.Errors)}");

            // Preparar objeto User de Microsoft Graph
            var user = new GraphUser
            {
                UserPrincipalName = dto.Email,
                DisplayName = dto.DisplayName,
                GivenName = dto.GivenName,
                Surname = dto.Surname,
                MailNickname = dto.MailNickname ?? dto.Email.Split('@')[0],
                JobTitle = dto.JobTitle,
                Department = dto.Department,
                OfficeLocation = dto.OfficeLocation,
                MobilePhone = dto.MobilePhone,
                StreetAddress = dto.StreetAddress,
                City = dto.City,
                State = dto.State,
                Country = dto.Country,
                PostalCode = dto.PostalCode,
                UsageLocation = dto.UsageLocation,
                EmployeeId = dto.EmployeeId,
                CompanyName = dto.CompanyName,
                AccountEnabled = dto.AccountEnabled,
                PasswordProfile = new PasswordProfile
                {
                    Password = dto.Password,
                    ForceChangePasswordNextSignIn = dto.ForceChangePasswordNextSignIn
                }
            };

            // Agregar teléfonos de negocio si se proporcionan
            if (!string.IsNullOrWhiteSpace(dto.BusinessPhones))
            {
                user.BusinessPhones = dto.BusinessPhones.Split(',').Select(p => p.Trim()).ToList();
            }

            // Llamar a Microsoft Graph API
            var createdUser = await _graphClient.Users.PostAsync(user);

            if (createdUser == null)
                throw new Exception("Error al crear usuario en Azure AD");

            // Sincronizar con BD Local
            await _azureAdRepo.CreateOrUpdateFromAzureAsync(
                createdUser.Id!,
                createdUser.UserPrincipalName!,
                createdUser.DisplayName!
            );

            // Registrar en log de sincronización
            await _azureAdRepo.LogAzureSyncAsync(
                syncType: "UserCreated",
                processed: 1,
                created: 1,
                updated: 0,
                errors: 0,
                details: $"Usuario creado: {dto.Email}"
            );

            // Registrar en auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "CreateAzureUser",
                Module = "AzureManagement",
                EntityId = createdUser.Id,
                NewValues = System.Text.Json.JsonSerializer.Serialize(new { dto.Email, dto.DisplayName }),
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Usuario creado exitosamente en Azure AD: {dto.Email}");

            return MapToAzureUserDto(createdUser);
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error de Microsoft Graph al crear usuario: {ex.Message}");
            throw new Exception($"Error al crear usuario en Azure AD: {ex.Message}", ex);
        }
    }

    public async Task<AzureUserDto?> GetUserFromAzureAsync(string azureObjectId)
    {
        try
        {
            var user = await _graphClient.Users[azureObjectId].GetAsync(config =>
            {
                config.QueryParameters.Select = new[] { 
                    "id", "userPrincipalName", "displayName", "givenName", "surname",
                    "jobTitle", "department", "officeLocation", "mobilePhone", "businessPhones",
                    "streetAddress", "city", "state", "country", "postalCode", "usageLocation",
                    "employeeId", "companyName", "accountEnabled", "createdDateTime",
                    "lastPasswordChangeDateTime", "userType", "assignedLicenses"
                };
            });

            return user != null ? MapToAzureUserDto(user) : null;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener usuario de Azure AD: {ex.Message}");
            return null;
        }
    }

    public async Task<AzureUserDto?> GetUserByEmailFromAzureAsync(string email)
    {
        try
        {
            var users = await _graphClient.Users.GetAsync(config =>
            {
                config.QueryParameters.Filter = $"userPrincipalName eq '{email}'";
                config.QueryParameters.Select = new[] { 
                    "id", "userPrincipalName", "displayName", "givenName", "surname",
                    "jobTitle", "department", "officeLocation", "mobilePhone", "businessPhones",
                    "accountEnabled", "createdDateTime", "userType"
                };
            });

            var user = users?.Value?.FirstOrDefault();
            return user != null ? MapToAzureUserDto(user) : null;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al buscar usuario por email en Azure AD: {ex.Message}");
            return null;
        }
    }

    public async Task<AzureUserDto?> UpdateUserInAzureAsync(string azureObjectId, UpdateAzureUserDto dto)
    {
        try
        {
            _logger.LogInformation($"Actualizando usuario en Azure AD: {azureObjectId}");

            var user = new GraphUser
            {
                DisplayName = dto.DisplayName,
                GivenName = dto.GivenName,
                Surname = dto.Surname,
                JobTitle = dto.JobTitle,
                Department = dto.Department,
                OfficeLocation = dto.OfficeLocation,
                MobilePhone = dto.MobilePhone,
                StreetAddress = dto.StreetAddress,
                City = dto.City,
                State = dto.State,
                Country = dto.Country,
                PostalCode = dto.PostalCode,
                UsageLocation = dto.UsageLocation,
                EmployeeId = dto.EmployeeId,
                CompanyName = dto.CompanyName,
                AccountEnabled = dto.AccountEnabled
            };

            if (!string.IsNullOrWhiteSpace(dto.BusinessPhones))
            {
                user.BusinessPhones = dto.BusinessPhones.Split(',').Select(p => p.Trim()).ToList();
            }

            await _graphClient.Users[azureObjectId].PatchAsync(user);

            // Obtener usuario actualizado
            var updatedUser = await GetUserFromAzureAsync(azureObjectId);

            if (updatedUser != null)
            {
                // Actualizar en BD local
                await _azureAdRepo.CreateOrUpdateFromAzureAsync(
                    azureObjectId,
                    updatedUser.Email,
                    updatedUser.DisplayName
                );

                // Log de sincronización
                await _azureAdRepo.LogAzureSyncAsync(
                    syncType: "UserUpdated",
                    processed: 1,
                    created: 0,
                    updated: 1,
                    errors: 0,
                    details: $"Usuario actualizado: {updatedUser.Email}"
                );

                // Auditoría
                await _context.AuditLogs.AddAsync(new AuditLog
                {
                    Action = "UpdateAzureUser",
                    Module = "AzureManagement",
                    EntityId = azureObjectId,
                    NewValues = System.Text.Json.JsonSerializer.Serialize(dto),
                    Timestamp = DateTime.UtcNow
                });
                await _context.SaveChangesAsync();
            }

            _logger.LogInformation($"Usuario actualizado exitosamente en Azure AD: {azureObjectId}");

            return updatedUser;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al actualizar usuario en Azure AD: {ex.Message}");
            throw new Exception($"Error al actualizar usuario: {ex.Message}", ex);
        }
    }

    public async Task<bool> EnableDisableUserInAzureAsync(string azureObjectId, bool enable)
    {
        try
        {
            var user = new GraphUser { AccountEnabled = enable };
            await _graphClient.Users[azureObjectId].PatchAsync(user);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = enable ? "EnableAzureUser" : "DisableAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"AccountEnabled: {enable}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Usuario {(enable ? "habilitado" : "deshabilitado")} en Azure AD: {azureObjectId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al {(enable ? "habilitar" : "deshabilitar")} usuario: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> DeleteUserFromAzureAsync(string azureObjectId, bool permanentDelete = false)
    {
        try
        {
            await _graphClient.Users[azureObjectId].DeleteAsync();

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "DeleteAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"PermanentDelete: {permanentDelete}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Usuario eliminado de Azure AD: {azureObjectId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al eliminar usuario de Azure AD: {ex.Message}");
            return false;
        }
    }

    public async Task<PagedResult<AzureUserDto>> ListUsersFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null)
    {
        try
        {
            var users = await _graphClient.Users.GetAsync(config =>
            {
                config.QueryParameters.Top = pageSize;
                if (!string.IsNullOrWhiteSpace(filter))
                {
                    config.QueryParameters.Filter = filter;
                }
                config.QueryParameters.Select = new[] { 
                    "id", "userPrincipalName", "displayName", "givenName", "surname",
                    "jobTitle", "department", "accountEnabled", "createdDateTime", "userType"
                };
                config.QueryParameters.Orderby = new[] { "displayName" };
            });

            var userDtos = users?.Value?.Select(MapToAzureUserDto).ToList() ?? new List<AzureUserDto>();
            var totalCount = users?.OdataCount ?? userDtos.Count;

            return new PagedResult<AzureUserDto>(
                Items: userDtos,
                CurrentPage: page,
                PageSize: pageSize,
                TotalItems: (int)totalCount,
                TotalPages: (int)Math.Ceiling((double)totalCount / pageSize),
                HasNextPage: page * pageSize < totalCount,
                HasPreviousPage: page > 1
            );
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al listar usuarios de Azure AD: {ex.Message}");
            return new PagedResult<AzureUserDto>(
                new List<AzureUserDto>(), page, pageSize, 0, 0, false, false
            );
        }
    }

    // ========== GESTIÓN DE CONTRASEÑAS ==========

    public async Task<string> ResetPasswordInAzureAsync(string azureObjectId, bool forceChange = true)
    {
        try
        {
            var tempPassword = GenerateSecurePasswordAsync().Result;

            var user = new GraphUser
            {
                PasswordProfile = new PasswordProfile
                {
                    Password = tempPassword,
                    ForceChangePasswordNextSignIn = forceChange
                }
            };

            await _graphClient.Users[azureObjectId].PatchAsync(user);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "ResetPasswordAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"ForceChange: {forceChange}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Contraseña reseteada para usuario: {azureObjectId}");
            return tempPassword;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al resetear contraseña: {ex.Message}");
            throw new Exception($"Error al resetear contraseña: {ex.Message}", ex);
        }
    }

    public async Task<bool> ChangePasswordInAzureAsync(string azureObjectId, string newPassword, bool forceChangeNextSignIn = false)
    {
        try
        {
            // Validar contraseña
            var validation = await ValidatePasswordPolicyAsync(newPassword);
            if (!validation.IsValid)
                throw new ArgumentException($"Contraseña no cumple con la política: {string.Join(", ", validation.Errors)}");

            var user = new GraphUser
            {
                PasswordProfile = new PasswordProfile
                {
                    Password = newPassword,
                    ForceChangePasswordNextSignIn = forceChangeNextSignIn
                }
            };

            await _graphClient.Users[azureObjectId].PatchAsync(user);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "ChangePasswordAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Contraseña cambiada para usuario: {azureObjectId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al cambiar contraseña: {ex.Message}");
            return false;
        }
    }

    public Task<PasswordValidationResult> ValidatePasswordPolicyAsync(string password)
    {
        var errors = new List<string>();
        var score = 0;

        if (string.IsNullOrWhiteSpace(password))
        {
            errors.Add("La contraseña no puede estar vacía");
            return Task.FromResult(new PasswordValidationResult(false, errors, 0, "Muy débil"));
        }

        // Longitud mínima
        if (password.Length < 8)
            errors.Add("La contraseña debe tener al menos 8 caracteres");
        else
            score += 20;

        // Mayúsculas
        if (!Regex.IsMatch(password, @"[A-Z]"))
            errors.Add("La contraseña debe contener al menos una letra mayúscula");
        else
            score += 20;

        // Minúsculas
        if (!Regex.IsMatch(password, @"[a-z]"))
            errors.Add("La contraseña debe contener al menos una letra minúscula");
        else
            score += 20;

        // Números
        if (!Regex.IsMatch(password, @"[0-9]"))
            errors.Add("La contraseña debe contener al menos un número");
        else
            score += 20;

        // Caracteres especiales
        if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]"))
            errors.Add("La contraseña debe contener al menos un carácter especial");
        else
            score += 20;

        // Longitud adicional
        if (password.Length >= 12)
            score += 10;
        if (password.Length >= 16)
            score += 10;

        var strengthLevel = score switch
        {
            >= 80 => "Muy fuerte",
            >= 60 => "Fuerte",
            >= 40 => "Media",
            >= 20 => "Débil",
            _ => "Muy débil"
        };

        return Task.FromResult(new PasswordValidationResult(
            errors.Count == 0,
            errors,
            score,
            strengthLevel
        ));
    }

    public Task<string> GenerateSecurePasswordAsync()
    {
        const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowercase = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*()_+-=[]{}";

        var password = new StringBuilder();
        var random = RandomNumberGenerator.Create();

        // Asegurar al menos un carácter de cada tipo
        password.Append(GetRandomChar(uppercase, random));
        password.Append(GetRandomChar(lowercase, random));
        password.Append(GetRandomChar(digits, random));
        password.Append(GetRandomChar(special, random));

        // Completar hasta 16 caracteres
        var allChars = uppercase + lowercase + digits + special;
        for (int i = 4; i < 16; i++)
        {
            password.Append(GetRandomChar(allChars, random));
        }

        // Mezclar los caracteres
        return Task.FromResult(new string(password.ToString().OrderBy(x => Guid.NewGuid()).ToArray()));
    }

    private char GetRandomChar(string chars, RandomNumberGenerator random)
    {
        var bytes = new byte[4];
        random.GetBytes(bytes);
        var index = BitConverter.ToUInt32(bytes, 0) % chars.Length;
        return chars[(int)index];
    }

    // ========== GESTIÓN DE ROLES DE DIRECTORIO ==========

    public async Task<IEnumerable<AzureRoleDto>> GetAllAzureDirectoryRolesAsync()
    {
        try
        {
            var roles = await _graphClient.DirectoryRoles.GetAsync();

            return roles?.Value?.Select(r => new AzureRoleDto(
                Id: r.Id!,
                DisplayName: r.DisplayName!,
                Description: r.Description,
                IsBuiltIn: true,
                RoleTemplateId: r.RoleTemplateId,
                RolePermissions: null
            )) ?? Enumerable.Empty<AzureRoleDto>();
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener roles de directorio: {ex.Message}");
            return Enumerable.Empty<AzureRoleDto>();
        }
    }

    public async Task<IEnumerable<AzureRoleDto>> GetUserAzureRolesAsync(string azureObjectId)
    {
        try
        {
            var memberOf = await _graphClient.Users[azureObjectId].MemberOf.GetAsync();

            var roles = memberOf?.Value?
                .OfType<DirectoryRole>()
                .Select(r => new AzureRoleDto(
                    Id: r.Id!,
                    DisplayName: r.DisplayName!,
                    Description: r.Description,
                    IsBuiltIn: true,
                    RoleTemplateId: r.RoleTemplateId,
                    RolePermissions: null
                )) ?? Enumerable.Empty<AzureRoleDto>();

            return roles;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener roles del usuario: {ex.Message}");
            return Enumerable.Empty<AzureRoleDto>();
        }
    }

    public async Task<bool> AssignAzureRoleAsync(string azureObjectId, string roleId)
    {
        try
        {
            var requestBody = new ReferenceCreate
            {
                OdataId = $"https://graph.microsoft.com/v1.0/directoryObjects/{azureObjectId}"
            };

            await _graphClient.DirectoryRoles[roleId].Members.Ref.PostAsync(requestBody);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "AssignAzureRole",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"RoleId: {roleId}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Rol {roleId} asignado a usuario {azureObjectId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al asignar rol: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> RemoveAzureRoleAsync(string azureObjectId, string roleId)
    {
        try
        {
            await _graphClient.DirectoryRoles[roleId].Members[azureObjectId].Ref.DeleteAsync();

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "RemoveAzureRole",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                OldValues = $"RoleId: {roleId}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Rol {roleId} removido de usuario {azureObjectId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al remover rol: {ex.Message}");
            return false;
        }
    }

    public async Task<IEnumerable<AzureUserDto>> GetRoleMembersAsync(string roleId)
    {
        try
        {
            var members = await _graphClient.DirectoryRoles[roleId].Members.GetAsync();

            var users = members?.Value?
                .OfType<GraphUser>()
                .Select(MapToAzureUserDto) ?? Enumerable.Empty<AzureUserDto>();

            return users;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener miembros del rol: {ex.Message}");
            return Enumerable.Empty<AzureUserDto>();
        }
    }

    // ========== GESTIÓN DE GRUPOS ==========

    public async Task<AzureGroupDto> CreateGroupInAzureAsync(CreateAzureGroupDto dto)
    {
        try
        {
            var group = new GraphGroup
            {
                DisplayName = dto.DisplayName,
                Description = dto.Description,
                MailNickname = dto.MailNickname ?? dto.DisplayName.Replace(" ", "").ToLower(),
                MailEnabled = dto.MailEnabled,
                SecurityEnabled = dto.SecurityEnabled,
                GroupTypes = dto.GroupType == "Microsoft365" ? new List<string> { "Unified" } : new List<string>()
            };

            var createdGroup = await _graphClient.Groups.PostAsync(group);

            if (createdGroup == null)
                throw new Exception("Error al crear grupo en Azure AD");

            // Agregar owners si se proporcionan
            if (dto.Owners != null && dto.Owners.Any())
            {
                foreach (var ownerId in dto.Owners)
                {
                    try
                    {
                        var ownerRef = new ReferenceCreate
                        {
                            OdataId = $"https://graph.microsoft.com/v1.0/users/{ownerId}"
                        };
                        await _graphClient.Groups[createdGroup.Id].Owners.Ref.PostAsync(ownerRef);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning($"Error al agregar owner {ownerId}: {ex.Message}");
                    }
                }
            }

            // Agregar members si se proporcionan
            if (dto.Members != null && dto.Members.Any())
            {
                foreach (var memberId in dto.Members)
                {
                    await AddUserToAzureGroupAsync(createdGroup.Id!, memberId);
                }
            }

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "CreateAzureGroup",
                Module = "AzureManagement",
                EntityId = createdGroup.Id,
                NewValues = System.Text.Json.JsonSerializer.Serialize(new { dto.DisplayName, dto.GroupType }),
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Grupo creado en Azure AD: {dto.DisplayName}");

            return new AzureGroupDto(
                Id: createdGroup.Id!,
                DisplayName: createdGroup.DisplayName!,
                Description: createdGroup.Description,
                Mail: createdGroup.Mail,
                MailNickname: createdGroup.MailNickname,
                MailEnabled: createdGroup.MailEnabled ?? false,
                SecurityEnabled: createdGroup.SecurityEnabled ?? false,
                GroupType: dto.GroupType,
                CreatedDateTime: createdGroup.CreatedDateTime?.DateTime,
                MemberCount: 0,
                GroupTypes: createdGroup.GroupTypes?.ToList()
            );
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al crear grupo: {ex.Message}");
            throw new Exception($"Error al crear grupo: {ex.Message}", ex);
        }
    }

    public async Task<AzureGroupDto?> GetGroupFromAzureAsync(string groupId)
    {
        try
        {
            var group = await _graphClient.Groups[groupId].GetAsync(config =>
            {
                config.QueryParameters.Select = new[] {
                    "id", "displayName", "description", "mail", "mailNickname",
                    "mailEnabled", "securityEnabled", "groupTypes", "createdDateTime"
                };
            });

            if (group == null) return null;

            // Obtener cantidad de miembros
            var members = await _graphClient.Groups[groupId].Members.GetAsync();
            var memberCount = members?.Value?.Count ?? 0;

            return new AzureGroupDto(
                Id: group.Id!,
                DisplayName: group.DisplayName!,
                Description: group.Description,
                Mail: group.Mail,
                MailNickname: group.MailNickname,
                MailEnabled: group.MailEnabled ?? false,
                SecurityEnabled: group.SecurityEnabled ?? false,
                GroupType: group.GroupTypes?.Contains("Unified") == true ? "Microsoft365" : "Security",
                CreatedDateTime: group.CreatedDateTime?.DateTime,
                MemberCount: memberCount,
                GroupTypes: group.GroupTypes?.ToList()
            );
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener grupo: {ex.Message}");
            return null;
        }
    }

    public async Task<AzureGroupDto?> UpdateGroupInAzureAsync(string groupId, UpdateAzureGroupDto dto)
    {
        try
        {
            var group = new GraphGroup
            {
                DisplayName = dto.DisplayName,
                Description = dto.Description,
                MailNickname = dto.MailNickname
            };

            await _graphClient.Groups[groupId].PatchAsync(group);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "UpdateAzureGroup",
                Module = "AzureManagement",
                EntityId = groupId,
                NewValues = System.Text.Json.JsonSerializer.Serialize(dto),
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            return await GetGroupFromAzureAsync(groupId);
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al actualizar grupo: {ex.Message}");
            return null;
        }
    }

    public async Task<bool> DeleteGroupFromAzureAsync(string groupId)
    {
        try
        {
            await _graphClient.Groups[groupId].DeleteAsync();

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "DeleteAzureGroup",
                Module = "AzureManagement",
                EntityId = groupId,
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Grupo eliminado: {groupId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al eliminar grupo: {ex.Message}");
            return false;
        }
    }

    public async Task<PagedResult<AzureGroupDto>> ListGroupsFromAzureAsync(int page = 1, int pageSize = 50, string? filter = null)
    {
        try
        {
            var groups = await _graphClient.Groups.GetAsync(config =>
            {
                config.QueryParameters.Top = pageSize;
                if (!string.IsNullOrWhiteSpace(filter))
                {
                    config.QueryParameters.Filter = filter;
                }
                config.QueryParameters.Select = new[] {
                    "id", "displayName", "description", "mail", "mailEnabled",
                    "securityEnabled", "groupTypes", "createdDateTime"
                };
                config.QueryParameters.Orderby = new[] { "displayName" };
            });

            var groupDtos = new List<AzureGroupDto>();
            if (groups?.Value != null)
            {
                foreach (var group in groups.Value)
                {
                    groupDtos.Add(new AzureGroupDto(
                        Id: group.Id!,
                        DisplayName: group.DisplayName!,
                        Description: group.Description,
                        Mail: group.Mail,
                        MailNickname: group.MailNickname,
                        MailEnabled: group.MailEnabled ?? false,
                        SecurityEnabled: group.SecurityEnabled ?? false,
                        GroupType: group.GroupTypes?.Contains("Unified") == true ? "Microsoft365" : "Security",
                        CreatedDateTime: group.CreatedDateTime?.DateTime,
                        MemberCount: 0,
                        GroupTypes: group.GroupTypes?.ToList()
                    ));
                }
            }

            var totalCount = groups?.OdataCount ?? groupDtos.Count;

            return new PagedResult<AzureGroupDto>(
                Items: groupDtos,
                CurrentPage: page,
                PageSize: pageSize,
                TotalItems: (int)totalCount,
                TotalPages: (int)Math.Ceiling((double)totalCount / pageSize),
                HasNextPage: page * pageSize < totalCount,
                HasPreviousPage: page > 1
            );
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al listar grupos: {ex.Message}");
            return new PagedResult<AzureGroupDto>(
                new List<AzureGroupDto>(), page, pageSize, 0, 0, false, false
            );
        }
    }

    public async Task<bool> AddUserToAzureGroupAsync(string groupId, string azureObjectId)
    {
        try
        {
            var requestBody = new ReferenceCreate
            {
                OdataId = $"https://graph.microsoft.com/v1.0/directoryObjects/{azureObjectId}"
            };

            await _graphClient.Groups[groupId].Members.Ref.PostAsync(requestBody);

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "AddUserToAzureGroup",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"GroupId: {groupId}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Usuario {azureObjectId} agregado al grupo {groupId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al agregar usuario al grupo: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> RemoveUserFromAzureGroupAsync(string groupId, string azureObjectId)
    {
        try
        {
            await _graphClient.Groups[groupId].Members[azureObjectId].Ref.DeleteAsync();

            // Auditoría
            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "RemoveUserFromAzureGroup",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                OldValues = $"GroupId: {groupId}",
                Timestamp = DateTime.UtcNow
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Usuario {azureObjectId} removido del grupo {groupId}");
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al remover usuario del grupo: {ex.Message}");
            return false;
        }
    }

    public async Task<IEnumerable<AzureUserDto>> GetGroupMembersAsync(string groupId)
    {
        try
        {
            var members = await _graphClient.Groups[groupId].Members.GetAsync();

            var users = members?.Value?
                .OfType<GraphUser>()
                .Select(MapToAzureUserDto) ?? Enumerable.Empty<AzureUserDto>();

            return users;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener miembros del grupo: {ex.Message}");
            return Enumerable.Empty<AzureUserDto>();
        }
    }

    public async Task<IEnumerable<AzureGroupDto>> GetUserAzureGroupsAsync(string azureObjectId)
    {
        try
        {
            var memberOf = await _graphClient.Users[azureObjectId].MemberOf.GetAsync();

            var groups = memberOf?.Value?
                .OfType<GraphGroup>()
                .Select(g => new AzureGroupDto(
                    Id: g.Id!,
                    DisplayName: g.DisplayName!,
                    Description: g.Description,
                    Mail: g.Mail,
                    MailNickname: g.MailNickname,
                    MailEnabled: g.MailEnabled ?? false,
                    SecurityEnabled: g.SecurityEnabled ?? false,
                    GroupType: g.GroupTypes?.Contains("Unified") == true ? "Microsoft365" : "Security",
                    CreatedDateTime: g.CreatedDateTime?.DateTime,
                    MemberCount: 0,
                    GroupTypes: g.GroupTypes?.ToList()
                )) ?? Enumerable.Empty<AzureGroupDto>();

            return groups;
        }
        catch (ServiceException ex)
        {
            _logger.LogError($"Error al obtener grupos del usuario: {ex.Message}");
            return Enumerable.Empty<AzureGroupDto>();
        }
    }

    // ========== OPERACIONES MASIVAS ==========

    public async Task<BulkOperationResult> BulkCreateUsersAsync(IEnumerable<CreateAzureUserDto> users)
    {
        var stopwatch = Stopwatch.StartNew();
        var successful = 0;
        var failed = 0;
        var errors = new List<BulkOperationError>();

        foreach (var userDto in users)
        {
            try
            {
                await CreateUserInAzureAsync(userDto);
                successful++;
            }
            catch (Exception ex)
            {
                failed++;
                errors.Add(new BulkOperationError(
                    Identifier: userDto.Email,
                    ErrorMessage: ex.Message,
                    ErrorCode: "CREATE_FAILED"
                ));
            }
        }

        stopwatch.Stop();

        return new BulkOperationResult(
            TotalRequested: users.Count(),
            Successful: successful,
            Failed: failed,
            Errors: errors,
            Duration: stopwatch.Elapsed
        );
    }

    public async Task<BulkOperationResult> BulkAddUsersToGroupAsync(string groupId, IEnumerable<string> userIds)
    {
        var stopwatch = Stopwatch.StartNew();
        var successful = 0;
        var failed = 0;
        var errors = new List<BulkOperationError>();

        foreach (var userId in userIds)
        {
            try
            {
                var result = await AddUserToAzureGroupAsync(groupId, userId);
                if (result)
                    successful++;
                else
                {
                    failed++;
                    errors.Add(new BulkOperationError(userId, "Failed to add user to group", "ADD_FAILED"));
                }
            }
            catch (Exception ex)
            {
                failed++;
                errors.Add(new BulkOperationError(userId, ex.Message, "ADD_FAILED"));
            }
        }

        stopwatch.Stop();

        return new BulkOperationResult(
            TotalRequested: userIds.Count(),
            Successful: successful,
            Failed: failed,
            Errors: errors,
            Duration: stopwatch.Elapsed
        );
    }

    // ========== SINCRONIZACIÓN ==========

    public async Task<SyncResult> SyncUserToLocalDbAsync(string azureObjectId)
    {
        var stopwatch = Stopwatch.StartNew();
        var errors = new List<string>();

        try
        {
            var user = await GetUserFromAzureAsync(azureObjectId);

            if (user == null)
            {
                errors.Add($"Usuario no encontrado en Azure AD: {azureObjectId}");
                return new SyncResult(
                    Success: false,
                    UsersProcessed: 0,
                    UsersCreated: 0,
                    UsersUpdated: 0,
                    UsersFailed: 1,
                    GroupsProcessed: 0,
                    GroupsCreated: 0,
                    GroupsUpdated: 0,
                    Errors: errors,
                    SyncDateTime: DateTime.UtcNow,
                    Duration: stopwatch.Elapsed
                );
            }

            var existingUser = await _azureAdRepo.FindByAzureIdAsync(Guid.Parse(azureObjectId));
            var isNew = existingUser == null;

            await _azureAdRepo.CreateOrUpdateFromAzureAsync(
                azureObjectId,
                user.Email,
                user.DisplayName
            );

            await _azureAdRepo.LogAzureSyncAsync(
                syncType: "ManualSync",
                processed: 1,
                created: isNew ? 1 : 0,
                updated: isNew ? 0 : 1,
                errors: 0,
                details: $"Usuario sincronizado: {user.Email}"
            );

            stopwatch.Stop();

            return new SyncResult(
                Success: true,
                UsersProcessed: 1,
                UsersCreated: isNew ? 1 : 0,
                UsersUpdated: isNew ? 0 : 1,
                UsersFailed: 0,
                GroupsProcessed: 0,
                GroupsCreated: 0,
                GroupsUpdated: 0,
                Errors: errors,
                SyncDateTime: DateTime.UtcNow,
                Duration: stopwatch.Elapsed
            );
        }
        catch (Exception ex)
        {
            errors.Add($"Error al sincronizar usuario: {ex.Message}");
            stopwatch.Stop();

            return new SyncResult(
                Success: false,
                UsersProcessed: 0,
                UsersCreated: 0,
                UsersUpdated: 0,
                UsersFailed: 1,
                GroupsProcessed: 0,
                GroupsCreated: 0,
                GroupsUpdated: 0,
                Errors: errors,
                SyncDateTime: DateTime.UtcNow,
                Duration: stopwatch.Elapsed
            );
        }
    }

    // ========== MÉTODOS AUXILIARES ==========

    private AzureUserDto MapToAzureUserDto(GraphUser user)
    {
        return new AzureUserDto(
            Id: user.Id!,
            Email: user.UserPrincipalName!,
            DisplayName: user.DisplayName!,
            GivenName: user.GivenName,
            Surname: user.Surname,
            JobTitle: user.JobTitle,
            Department: user.Department,
            OfficeLocation: user.OfficeLocation,
            MobilePhone: user.MobilePhone,
            BusinessPhones: user.BusinessPhones?.ToList(),
            StreetAddress: user.StreetAddress,
            City: user.City,
            State: user.State,
            Country: user.Country,
            PostalCode: user.PostalCode,
            UsageLocation: user.UsageLocation,
            EmployeeId: user.EmployeeId,
            CompanyName: user.CompanyName,
            AccountEnabled: user.AccountEnabled ?? false,
            CreatedDateTime: user.CreatedDateTime?.DateTime,
            LastPasswordChangeDateTime: user.LastPasswordChangeDateTime?.DateTime,
            UserType: user.UserType,
            AssignedLicenses: user.AssignedLicenses?.Select(l => l.SkuId.ToString()!).ToList()
        );
    }

    private bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}
