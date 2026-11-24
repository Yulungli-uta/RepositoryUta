namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>Resumen de acceso de un usuario (cabecera de la pestaña "Actividad de acceso").</summary>
public record UserAccessSummaryDto(
    Guid UserId,
    string Email,
    string? DisplayName,
    string UserType,
    bool IsActive,
    int? HrEmployeeId,
    string[] Roles,
    DateTime? LastMicrosoftLogin,
    DateTime? LastAppAccess,
    int ValidSessions,
    bool AccountLocked,
    DateTime? LockedUntil);

/// <summary>Un evento de la línea de tiempo (inicio de sesión, renovación, cierre, anomalía...).</summary>
public record UserAccessEventDto(
    DateTime Timestamp,
    string Type,
    string Title,
    string? Detail,
    string? IpAddress,
    string? Device,
    Guid? SessionId);

public record UserAccessTimelineDto(
    UserAccessSummaryDto Summary,
    IReadOnlyList<UserAccessEventDto> Items,
    int Page,
    int PageSize,
    int TotalCount,
    int TotalPages);
