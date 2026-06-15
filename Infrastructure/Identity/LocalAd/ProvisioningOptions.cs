namespace WsSeguUta.AuthSystem.API.Infrastructure.Identity.LocalAd;

/// <summary>
/// Configuración de aprovisionamiento automático de empleados.
/// Se lee de la sección "Provisioning" en appsettings.json.
/// </summary>
public sealed class ProvisioningOptions
{
    public const string Section = "Provisioning";

    /// <summary>
    /// Nombres de los roles (auth.tbl_Roles.Name) que se asignan automáticamente
    /// al crear un empleado nuevo. Se iteran todos; los que no existan en BD se
    /// loguean como error y se omiten sin detener el aprovisionamiento.
    /// Ejemplo: ["Empleado", "Portal-Empleados"]
    /// </summary>
    public string[] DefaultRoleNames { get; init; } = ["Empleado"];

    /// <summary>
    /// CN del grupo AD para funcionarios activos (ej: UActivos).
    /// Los funcionarios se agregan a este grupo al crearse la cuenta.
    /// Vacío o null = no agregar automáticamente.
    /// </summary>
    public string? GrupoFuncionariosActivosCn { get; init; }

    /// <summary>
    /// CN del grupo AD para estudiantes activos (ej: EActivos).
    /// Los estudiantes se agregan a este grupo al crearse la cuenta.
    /// Vacío o null = no agregar automáticamente.
    /// </summary>
    public string? GrupoEstudiantesActivosCn { get; init; }

    /// <summary>
    /// TypeIds de HR.ref_Types que identifican a un empleado como estudiante.
    /// Se usa para elegir la OU y el grupo correcto (ESTUDIANTES vs USUARIOS) al deshabilitar.
    /// Dejar vacío hasta que se implemente la Fase 11 de aprovisionamiento de estudiantes.
    /// </summary>
    public int[] StudentEmployeeTypeIds { get; init; } = [];
}
