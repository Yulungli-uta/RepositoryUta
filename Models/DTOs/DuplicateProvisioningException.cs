namespace WsSeguUta.AuthSystem.API.Models.DTOs;

/// <summary>
/// Se lanza cuando se intenta aprovisionar un empleado que ya tiene una cuenta activa.
/// El controlador la convierte en HTTP 409 Conflict.
/// </summary>
public sealed class DuplicateProvisioningException : Exception
{
    public int HrEmployeeId { get; }
    public string ExistingEmail { get; }
    public string CurrentStatus { get; }

    public DuplicateProvisioningException(int hrEmployeeId, string existingEmail, string currentStatus)
        : base($"El empleado {hrEmployeeId} ya tiene una cuenta activa: {existingEmail} (estado: {currentStatus})")
    {
        HrEmployeeId  = hrEmployeeId;
        ExistingEmail = existingEmail;
        CurrentStatus = currentStatus;
    }
}
