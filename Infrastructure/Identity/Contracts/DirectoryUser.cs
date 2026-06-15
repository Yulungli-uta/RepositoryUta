namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.Contracts
{
    public sealed record DirectoryUser(
        string Id,
        string Email,
        string DisplayName,
        string? GivenName,
        string? Surname,
        string? JobTitle,
        string? Department,
        bool AccountEnabled,
        DateTimeOffset? CreatedDateTime,
        /// <summary>
        /// Populated when the CN had to be adjusted to avoid a collision in AD Local.
        /// Null = the original CN was used without conflict.
        /// Example: "CN 'María Lozano' already existed in AD, used 'María Lozano 1' instead."
        /// </summary>
        string? CnWarning = null,
        /// <summary>Número de cédula/identificación. Se persiste como atributo employeeID en AD.</summary>
        string? IdCard = null);
}
