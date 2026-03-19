using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Graph.Models.ODataErrors;
using Microsoft.Kiota.Abstractions;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WsSeguUta.AuthSystem.API.Data;
using WsSeguUta.AuthSystem.API.Data.Repositories;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Models.Entities;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using GraphGroup = Microsoft.Graph.Models.Group;
using GraphUser = Microsoft.Graph.Models.User;

namespace WsSeguUta.AuthSystem.API.Services.Implementations;

public class AzureManagementService : IAzureManagementService
{
    private const int DefaultPageSize = 50;
    private const int MaxPageSize = 200;

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
            _logger.LogInformation("Creando usuario en Azure AD: {Email}", dto.Email);

            if (!IsValidEmail(dto.Email))
                throw new ArgumentException("Email inválido");

            var passwordValidation = await ValidatePasswordPolicyAsync(dto.Password);
            if (!passwordValidation.IsValid)
                throw new ArgumentException($"Contraseña no cumple con la política: {string.Join(", ", passwordValidation.Errors)}");

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

            if (!string.IsNullOrWhiteSpace(dto.BusinessPhones))
                user.BusinessPhones = dto.BusinessPhones.Split(',').Select(p => p.Trim()).ToList();

            var createdUser = await _graphClient.Users.PostAsync(user);
            if (createdUser == null)
                throw new Exception("Error al crear usuario en Azure AD");

            await _azureAdRepo.CreateOrUpdateFromAzureAsync(
                createdUser.Id!,
                createdUser.UserPrincipalName!,
                createdUser.DisplayName!
            );

            await _azureAdRepo.LogAzureSyncAsync(
                syncType: "UserCreated",
                processed: 1,
                created: 1,
                updated: 0,
                errors: 0,
                details: $"Usuario creado: {dto.Email}"
            );

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "CreateAzureUser",
                Module = "AzureManagement",
                EntityId = createdUser.Id,
                NewValues = System.Text.Json.JsonSerializer.Serialize(new { dto.Email, dto.DisplayName }),
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            _logger.LogInformation("Usuario creado exitosamente en Azure AD: {Email}", dto.Email);
            return MapToAzureUserDto(createdUser);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error de Microsoft Graph al crear usuario. Email={Email}", dto.Email);
            throw new Exception($"Error al crear usuario en Azure AD: {ex.Message}", ex);
        }
    }

    public async Task<AzureUserDto?> GetUserFromAzureAsync(string azureObjectId)
    {
        try
        {
            _logger.LogDebug("GetUserFromAzureAsync: {AzureObjectId}", azureObjectId);

            var user = await _graphClient.Users[azureObjectId].GetAsync(config =>
            {
                config.QueryParameters.Select = new[]
                {
                    "id","userPrincipalName","displayName","givenName","surname",
                    "jobTitle","department","officeLocation","mobilePhone","businessPhones",
                    "streetAddress","city","state","country","postalCode","usageLocation",
                    "employeeId","companyName","accountEnabled","createdDateTime",
                    "lastPasswordChangeDateTime","userType","assignedLicenses"
                };
            });

            return user != null ? MapToAzureUserDto(user) : null;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al obtener usuario de Azure AD. AzureObjectId={AzureObjectId}", azureObjectId);
            return null;
        }
    }

    public async Task<AzureUserDto?> GetUserByEmailFromAzureAsync(string email)
    {
        try
        {
            var safe = email.Replace("'", "''").Trim();

            var users = await _graphClient.Users.GetAsync(config =>
            {
                config.QueryParameters.Filter = $"(userPrincipalName eq '{safe}' or mail eq '{safe}')";
                config.QueryParameters.Select = new[]
                {
                    "id","userPrincipalName","mail","displayName","givenName","surname",
                    "jobTitle","department","officeLocation","mobilePhone","businessPhones",
                    "accountEnabled","createdDateTime","userType"
                };
            });

            var user = users?.Value?.FirstOrDefault();
            return user != null ? MapToAzureUserDto(user) : null;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al buscar usuario por correo. Email={Email}", email);
            return null;
        }
    }

    public async Task<AzureUserDto?> UpdateUserInAzureAsync(string azureObjectId, UpdateAzureUserDto dto)
    {
        try
        {
            _logger.LogInformation("Actualizando usuario en Azure AD: {AzureObjectId}", azureObjectId);

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
                user.BusinessPhones = dto.BusinessPhones.Split(',').Select(p => p.Trim()).ToList();

            await _graphClient.Users[azureObjectId].PatchAsync(user);

            var updatedUser = await GetUserFromAzureAsync(azureObjectId);

            if (updatedUser != null)
            {
                await _azureAdRepo.CreateOrUpdateFromAzureAsync(
                    azureObjectId,
                    updatedUser.Email,
                    updatedUser.DisplayName
                );

                await _azureAdRepo.LogAzureSyncAsync(
                    syncType: "UserUpdated",
                    processed: 1,
                    created: 0,
                    updated: 1,
                    errors: 0,
                    details: $"Usuario actualizado: {updatedUser.Email}"
                );

                await _context.AuditLogs.AddAsync(new AuditLog
                {
                    Action = "UpdateAzureUser",
                    Module = "AzureManagement",
                    EntityId = azureObjectId,
                    NewValues = System.Text.Json.JsonSerializer.Serialize(dto),
                    Timestamp = DateTime.Now
                });

                await _context.SaveChangesAsync();
            }

            _logger.LogInformation("Usuario actualizado exitosamente en Azure AD: {AzureObjectId}", azureObjectId);
            return updatedUser;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al actualizar usuario en Azure AD. AzureObjectId={AzureObjectId}", azureObjectId);
            throw new Exception($"Error al actualizar usuario: {ex.Message}", ex);
        }
    }

    public async Task<bool> EnableDisableUserInAzureAsync(string azureObjectId, bool enable)
    {
        try
        {
            var user = new GraphUser { AccountEnabled = enable };
            await _graphClient.Users[azureObjectId].PatchAsync(user);

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = enable ? "EnableAzureUser" : "DisableAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"AccountEnabled: {enable}",
                Timestamp = DateTime.Now
            });

            await _context.SaveChangesAsync();
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al habilitar/deshabilitar usuario. AzureObjectId={AzureObjectId}", azureObjectId);
            return false;
        }
    }

    public async Task<bool> DeleteUserFromAzureAsync(string azureObjectId, bool permanentDelete = false)
    {
        try
        {
            await _graphClient.Users[azureObjectId].DeleteAsync();

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "DeleteAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"PermanentDelete: {permanentDelete}",
                Timestamp = DateTime.Now
            });

            await _context.SaveChangesAsync();
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al eliminar usuario de Azure AD. AzureObjectId={AzureObjectId}", azureObjectId);
            return false;
        }
    }

    public async Task<PagedResult<AzureUserDto>> ListUsersFromAzureAsync(int page = 1, int pageSize = DefaultPageSize, string? filter = null)
    {
        try
        {
            NormalizePaging(ref page, ref pageSize);

            _logger.LogInformation("Graph ListUsers: page={Page}, pageSize={PageSize}, filter={Filter}", page, pageSize, filter);

            var first = await _graphClient.Users.GetAsync(config =>
            {
                config.QueryParameters.Top = pageSize;
                config.QueryParameters.Count = true;

                if (!string.IsNullOrWhiteSpace(filter))
                    config.QueryParameters.Filter = filter;

                config.QueryParameters.Select = new[]
                {
                    "id","userPrincipalName","displayName","givenName","surname",
                    "jobTitle","department","accountEnabled","createdDateTime","userType"
                };

                config.QueryParameters.Orderby = new[] { "displayName" };
                config.Headers.Add("ConsistencyLevel", "eventual");
            });

            long? totalCount = first?.OdataCount;
            if (!totalCount.HasValue)
                totalCount = await GetUsersCountAsync(filter);

            var current = first;
            var hops = 1;
            while (hops < page && !string.IsNullOrWhiteSpace(current?.OdataNextLink))
            {
                current = await GetUsersByNextLinkAsync(current!.OdataNextLink!);
                hops++;
            }

            var items = current?.Value?.Select(MapToAzureUserDto).ToList() ?? new List<AzureUserDto>();
            var hasNext = !string.IsNullOrWhiteSpace(current?.OdataNextLink);

            var total = totalCount.HasValue ? (int)totalCount.Value : items.Count;
            var totalPages = total > 0 ? (int)Math.Ceiling(total / (double)pageSize) : 0;

            return new PagedResult<AzureUserDto>
            {
                Items = items,
                Page = page,
                PageSize = pageSize,
                TotalCount = total,
                TotalPages = totalPages,
                HasNextPage = hasNext,
                HasPreviousPage = page > 1
            };
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al listar usuarios de Azure AD");
            return new PagedResult<AzureUserDto>
            {
                Items = new List<AzureUserDto>(),
                Page = page,
                PageSize = pageSize,
                TotalCount = 0,
                TotalPages = 0,
                HasNextPage = false,
                HasPreviousPage = false
            };
        }
    }

    private async Task<long?> GetUsersCountAsync(string? filter)
    {
        var resp = await _graphClient.Users.GetAsync(config =>
        {
            config.QueryParameters.Top = 1;
            config.QueryParameters.Count = true;

            if (!string.IsNullOrWhiteSpace(filter))
                config.QueryParameters.Filter = filter;

            config.QueryParameters.Select = new[] { "id" };
            config.Headers.Add("ConsistencyLevel", "eventual");
        });

        return resp?.OdataCount;
    }

    private async Task<UserCollectionResponse?> GetUsersByNextLinkAsync(string nextLink)
    {
        if (string.IsNullOrWhiteSpace(nextLink)) return null;

        var requestInfo = new RequestInformation
        {
            HttpMethod = Method.GET,
            UrlTemplate = nextLink
        };

        requestInfo.PathParameters.Clear();
        requestInfo.Headers.Add("ConsistencyLevel", "eventual");

        return await _graphClient.RequestAdapter.SendAsync(
            requestInfo,
            UserCollectionResponse.CreateFromDiscriminatorValue,
            default
        );
    }

    // ========== GESTIÓN DE CONTRASEÑAS ==========

    public async Task<string> ResetPasswordInAzureAsync(string azureObjectId, bool forceChange = true)
    {
        try
        {
            var tempPassword = await GenerateSecurePasswordAsync();

            var user = new GraphUser
            {
                PasswordProfile = new PasswordProfile
                {
                    Password = tempPassword,
                    ForceChangePasswordNextSignIn = forceChange
                }
            };

            await _graphClient.Users[azureObjectId].PatchAsync(user);

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "ResetPasswordAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"ForceChange: {forceChange}",
                Timestamp = DateTime.Now
            });

            await _context.SaveChangesAsync();

            _logger.LogInformation("Contraseña reseteada para usuario: {AzureObjectId}", azureObjectId);
            return tempPassword;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al resetear contraseña. AzureObjectId={AzureObjectId}", azureObjectId);
            throw new Exception($"Error al resetear contraseña: {ex.Message}", ex);
        }
    }

    public async Task<bool> ChangePasswordInAzureAsync(string azureObjectId, string newPassword, bool forceChangeNextSignIn = false)
    {
        try
        {
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

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "ChangePasswordAzureUser",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                Timestamp = DateTime.Now
            });

            await _context.SaveChangesAsync();

            _logger.LogInformation("Contraseña cambiada para usuario: {AzureObjectId}", azureObjectId);
            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al cambiar contraseña. AzureObjectId={AzureObjectId}", azureObjectId);
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

        if (password.Length < 8) errors.Add("La contraseña debe tener al menos 8 caracteres"); else score += 20;
        if (!Regex.IsMatch(password, @"[A-Z]")) errors.Add("Debe contener al menos una mayúscula"); else score += 20;
        if (!Regex.IsMatch(password, @"[a-z]")) errors.Add("Debe contener al menos una minúscula"); else score += 20;
        if (!Regex.IsMatch(password, @"[0-9]")) errors.Add("Debe contener al menos un número"); else score += 20;
        if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>\/?]")) errors.Add("Debe contener al menos un carácter especial"); else score += 20;

        if (password.Length >= 12) score += 10;
        if (password.Length >= 16) score += 10;

        var strengthLevel = score switch
        {
            >= 80 => "Muy fuerte",
            >= 60 => "Fuerte",
            >= 40 => "Media",
            >= 20 => "Débil",
            _ => "Muy débil"
        };

        return Task.FromResult(new PasswordValidationResult(errors.Count == 0, errors, score, strengthLevel));
    }

    public Task<string> GenerateSecurePasswordAsync()
    {
        const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowercase = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789";
        const string special = "!@#$%^&*()_+-=[]{}";

        var password = new StringBuilder();
        using var rng = RandomNumberGenerator.Create();

        password.Append(GetRandomChar(uppercase, rng));
        password.Append(GetRandomChar(lowercase, rng));
        password.Append(GetRandomChar(digits, rng));
        password.Append(GetRandomChar(special, rng));

        var allChars = uppercase + lowercase + digits + special;
        for (int i = 4; i < 16; i++)
            password.Append(GetRandomChar(allChars, rng));

        // Mezclar (si quieres shuffle criptográfico, se puede implementar aparte)
        var mixed = new string(password.ToString().OrderBy(_ => Guid.NewGuid()).ToArray());
        return Task.FromResult(mixed);
    }

    private static char GetRandomChar(string chars, RandomNumberGenerator rng)
    {
        var bytes = new byte[4];
        rng.GetBytes(bytes);
        var index = BitConverter.ToUInt32(bytes, 0) % (uint)chars.Length;
        return chars[(int)index];
    }

    // ========== ROLES ==========

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
            _logger.LogError(ex, "Error al obtener roles de directorio");
            return Enumerable.Empty<AzureRoleDto>();
        }
    }

    public async Task<IEnumerable<AzureRoleDto>> GetUserAzureRolesAsync(string azureObjectId)
    {
        try
        {
            var results = new List<AzureRoleDto>();

            var page = await _graphClient.Users[azureObjectId].MemberOf.GetAsync(config =>
            {
                config.QueryParameters.Select = new[] { "id", "displayName", "description" };
            });

            while (page?.Value != null)
            {
                foreach (var obj in page.Value)
                {
                    if (obj is Microsoft.Graph.Models.Group g)
                    {
                        results.Add(new AzureRoleDto(
                            Id: g.Id!,
                            DisplayName: g.DisplayName ?? "(Sin nombre)",
                            Description: g.Description,
                            IsBuiltIn: false,
                            RoleTemplateId: null,
                            RolePermissions: null
                        ));
                    }
                    else if (obj is DirectoryRole r)
                    {
                        results.Add(new AzureRoleDto(
                            Id: r.Id!,
                            DisplayName: r.DisplayName ?? "(Sin nombre)",
                            Description: r.Description,
                            IsBuiltIn: true,
                            RoleTemplateId: r.RoleTemplateId,
                            RolePermissions: null
                        ));
                    }
                }

                if (string.IsNullOrEmpty(page.OdataNextLink))
                    break;

                page = await _graphClient.Users[azureObjectId].MemberOf
                    .WithUrl(page.OdataNextLink)
                    .GetAsync();
            }

            return results;
        }
        catch (ODataError ex)
        {
            _logger.LogError("Error Graph al obtener miembros del usuario: {Message}", ex.Error?.Message);
            return Enumerable.Empty<AzureRoleDto>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al obtener miembros del usuario");
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

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "AssignAzureRole",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"RoleId: {roleId}",
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al asignar rol. RoleId={RoleId}, AzureObjectId={AzureObjectId}", roleId, azureObjectId);
            return false;
        }
    }

    public async Task<bool> RemoveAzureRoleAsync(string azureObjectId, string roleId)
    {
        try
        {
            await _graphClient.DirectoryRoles[roleId].Members[azureObjectId].Ref.DeleteAsync();

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "RemoveAzureRole",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                OldValues = $"RoleId: {roleId}",
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al remover rol. RoleId={RoleId}, AzureObjectId={AzureObjectId}", roleId, azureObjectId);
            return false;
        }
    }

    public async Task<IEnumerable<AzureUserDto>> GetRoleMembersAsync(string roleId)
    {
        try
        {
            var members = await _graphClient.DirectoryRoles[roleId].Members.GetAsync();

            return members?.Value?
                .OfType<GraphUser>()
                .Select(MapToAzureUserDto) ?? Enumerable.Empty<AzureUserDto>();
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al obtener miembros del rol. RoleId={RoleId}", roleId);
            return Enumerable.Empty<AzureUserDto>();
        }
    }

    // ========== GRUPOS ==========

    public async Task<AzureGroupDto> CreateGroupInAzureAsync(CreateAzureGroupDto dto)
    {
        try
        {
            var group = new GraphGroup
            {
                DisplayName = dto.DisplayName,
                Description = dto.Description,
                MailNickname = dto.MailNickname ?? dto.DisplayName.Replace(" ", "").ToLowerInvariant(),
                MailEnabled = dto.MailEnabled,
                SecurityEnabled = dto.SecurityEnabled,
                GroupTypes = dto.GroupType == "Microsoft365" ? new List<string> { "Unified" } : new List<string>()
            };

            var createdGroup = await _graphClient.Groups.PostAsync(group);
            if (createdGroup == null)
                throw new Exception("Error al crear grupo en Azure AD");

            if (dto.Owners is { Count: > 0 })
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
                        _logger.LogWarning(ex, "Error al agregar owner {OwnerId}", ownerId);
                    }
                }
            }

            if (dto.Members is { Count: > 0 })
            {
                foreach (var memberId in dto.Members)
                    await AddUserToAzureGroupAsync(createdGroup.Id!, memberId);
            }

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "CreateAzureGroup",
                Module = "AzureManagement",
                EntityId = createdGroup.Id,
                NewValues = System.Text.Json.JsonSerializer.Serialize(new { dto.DisplayName, dto.GroupType }),
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

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
            _logger.LogError(ex, "Error al crear grupo");
            throw new Exception($"Error al crear grupo: {ex.Message}", ex);
        }
    }

    public async Task<AzureGroupDto?> GetGroupFromAzureAsync(string groupId)
    {
        try
        {
            var group = await _graphClient.Groups[groupId].GetAsync(config =>
            {
                config.QueryParameters.Select = new[]
                {
                    "id","displayName","description","mail","mailNickname",
                    "mailEnabled","securityEnabled","groupTypes","createdDateTime"
                };
            });

            if (group == null) return null;

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
            _logger.LogError(ex, "Error al obtener grupo. GroupId={GroupId}", groupId);
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

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "UpdateAzureGroup",
                Module = "AzureManagement",
                EntityId = groupId,
                NewValues = System.Text.Json.JsonSerializer.Serialize(dto),
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return await GetGroupFromAzureAsync(groupId);
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al actualizar grupo. GroupId={GroupId}", groupId);
            return null;
        }
    }

    public async Task<bool> DeleteGroupFromAzureAsync(string groupId)
    {
        try
        {
            await _graphClient.Groups[groupId].DeleteAsync();

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "DeleteAzureGroup",
                Module = "AzureManagement",
                EntityId = groupId,
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al eliminar grupo. GroupId={GroupId}", groupId);
            return false;
        }
    }

    public async Task<PagedResult<AzureGroupDto>> ListGroupsFromAzureAsync(int page = 1, int pageSize = DefaultPageSize, string? filter = null)
    {
        try
        {
            NormalizePaging(ref page, ref pageSize);

            var groups = await _graphClient.Groups.GetAsync(config =>
            {
                config.QueryParameters.Top = pageSize;

                if (!string.IsNullOrWhiteSpace(filter))
                    config.QueryParameters.Filter = filter;

                config.QueryParameters.Select = new[]
                {
                    "id","displayName","description","mail","mailEnabled",
                    "securityEnabled","groupTypes","createdDateTime"
                };
                config.QueryParameters.Orderby = new[] { "displayName" };
            });

            var items = new List<AzureGroupDto>();
            if (groups?.Value != null)
            {
                foreach (var g in groups.Value)
                {
                    items.Add(new AzureGroupDto(
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
                    ));
                }
            }

            var total = (int)(groups?.OdataCount ?? items.Count);
            var totalPages = total > 0 ? (int)Math.Ceiling(total / (double)pageSize) : 0;

            return new PagedResult<AzureGroupDto>
            {
                Items = items,
                Page = page,
                PageSize = pageSize,
                TotalCount = total,
                TotalPages = totalPages,
                HasNextPage = totalPages > 0 && page < totalPages,
                HasPreviousPage = page > 1
            };
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al listar grupos");
            return new PagedResult<AzureGroupDto>
            {
                Items = new List<AzureGroupDto>(),
                Page = page,
                PageSize = pageSize,
                TotalCount = 0,
                TotalPages = 0,
                HasNextPage = false,
                HasPreviousPage = false
            };
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

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "AddUserToAzureGroup",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                NewValues = $"GroupId: {groupId}",
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al agregar usuario al grupo. GroupId={GroupId}, AzureObjectId={AzureObjectId}", groupId, azureObjectId);
            return false;
        }
    }

    public async Task<bool> RemoveUserFromAzureGroupAsync(string groupId, string azureObjectId)
    {
        try
        {
            await _graphClient.Groups[groupId].Members[azureObjectId].Ref.DeleteAsync();

            await _context.AuditLogs.AddAsync(new AuditLog
            {
                Action = "RemoveUserFromAzureGroup",
                Module = "AzureManagement",
                EntityId = azureObjectId,
                OldValues = $"GroupId: {groupId}",
                Timestamp = DateTime.Now
            });
            await _context.SaveChangesAsync();

            return true;
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al remover usuario del grupo. GroupId={GroupId}, AzureObjectId={AzureObjectId}", groupId, azureObjectId);
            return false;
        }
    }

    public async Task<IEnumerable<AzureUserDto>> GetGroupMembersAsync(string groupId)
    {
        try
        {
            var members = await _graphClient.Groups[groupId].Members.GetAsync();

            return members?.Value?
                .OfType<GraphUser>()
                .Select(MapToAzureUserDto) ?? Enumerable.Empty<AzureUserDto>();
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al obtener miembros del grupo. GroupId={GroupId}", groupId);
            return Enumerable.Empty<AzureUserDto>();
        }
    }

    public async Task<IEnumerable<AzureGroupDto>> GetUserAzureGroupsAsync(string azureObjectId)
    {
        try
        {
            _logger.LogInformation("Obteniendo grupos del usuario {AzureObjectId} desde Azure AD", azureObjectId);

            var page = await _graphClient.Users[azureObjectId].MemberOf.GraphGroup.GetAsync(cfg =>
            {
                cfg.QueryParameters.Select = new[]
                {
                    "id","displayName","description","mail","mailNickname",
                    "mailEnabled","securityEnabled","groupTypes","createdDateTime"
                };
                cfg.QueryParameters.Top = 999;
            });

            var allGroups = new List<GraphGroup>();
            while (page?.Value != null)
            {
                allGroups.AddRange(page.Value);

                if (string.IsNullOrWhiteSpace(page.OdataNextLink))
                    break;

                var requestInfo = new RequestInformation
                {
                    HttpMethod = Method.GET,
                    UrlTemplate = page.OdataNextLink
                };
                requestInfo.PathParameters.Clear();

                page = await _graphClient.RequestAdapter.SendAsync(
                    requestInfo,
                    Microsoft.Graph.Models.GroupCollectionResponse.CreateFromDiscriminatorValue,
                    default
                );
            }

            var filtered = allGroups
                .Where(g => !string.IsNullOrWhiteSpace(g.DisplayName))
                .Where(g => g.DisplayName!.StartsWith("Rol", StringComparison.OrdinalIgnoreCase));

            return filtered.Select(g => new AzureGroupDto(
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
            ));
        }
        catch (ServiceException ex)
        {
            _logger.LogError(ex, "Error al obtener grupos del usuario. AzureObjectId={AzureObjectId}", azureObjectId);
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
                if (result) successful++;
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
                    SyncDateTime: DateTime.Now,
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
                SyncDateTime: DateTime.Now,
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
                SyncDateTime: DateTime.Now,
                Duration: stopwatch.Elapsed
            );
        }
    }

    // ========== MÉTODOS AUXILIARES ==========

    private static void NormalizePaging(ref int page, ref int pageSize)
    {
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = DefaultPageSize;
        if (pageSize > MaxPageSize) pageSize = MaxPageSize;
    }

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

    private static bool IsValidEmail(string email)
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