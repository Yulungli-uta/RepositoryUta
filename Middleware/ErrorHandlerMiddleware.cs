using System.DirectoryServices.Protocols;
using System.Net;
using System.Text.Json;

namespace WsSeguUta.AuthSystem.API.Middleware
{
  /// <summary>
  /// Manejador global de excepciones no controladas. Debe registrarse al INICIO del
  /// pipeline para envolver también CORS, rate limiter, authentication y authorization.
  /// Responde con un cuerpo JSON genérico + traceId: nunca expone el detalle interno
  /// de la excepción al cliente (este servicio es la fuente de verdad de auth);
  /// el detalle completo queda en el log correlacionado por traceId.
  /// </summary>
  public class ErrorHandlerMiddleware
  {
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlerMiddleware> _logger;

    public ErrorHandlerMiddleware(RequestDelegate next, ILogger<ErrorHandlerMiddleware> logger)
    {
      _next = next;
      _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
      try
      {
        await _next(context);
      }
      catch (Exception ex)
      {
        var traceId = context.TraceIdentifier;
        _logger.LogError(ex, "Excepción no controlada. TraceId: {TraceId}, Path: {Path}", traceId, context.Request.Path);

        // Si la respuesta ya comenzó a enviarse no es posible escribir el cuerpo
        // controlado; se relanza para que el servidor cierre la conexión.
        if (context.Response.HasStarted)
        {
          _logger.LogWarning("La respuesta ya inició; no se puede escribir el error controlado. TraceId: {TraceId}", traceId);
          throw;
        }

        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
        context.Response.ContentType = "application/json";

        // Errores de LDAP (bind fallido, servidor inalcanzable) son casi siempre un problema
        // de configuración/credenciales de la cuenta de servicio de AD, no un bug de la app —
        // se distingue del genérico para que el front pueda mostrar un mensaje accionable en
        // vez de "Error interno" sin dar pista de qué revisar. El detalle real (errorCode,
        // servidor, usuario) ya quedó en el log de arriba vía traceId; aquí no se expone.
        var isAdConfigError = ex is LdapException || ex is DirectoryOperationException;

        var body = JsonSerializer.Serialize(new
        {
          success = false,
          message = isAdConfigError ? "Error de configuración de Active Directory" : "Error interno",
          errors = new[]
          {
            isAdConfigError
              ? $"No se pudo conectar o autenticar contra Active Directory. Verifique la configuración de la cuenta de servicio. Referencia: {traceId}"
              : $"Ocurrió un error inesperado. Referencia: {traceId}"
          },
          traceId,
          timestamp = DateTime.Now
        });

        await context.Response.WriteAsync(body);
      }
    }
  }
}
