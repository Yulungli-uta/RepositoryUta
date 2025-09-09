using System.Net; using System.Text.Json;
namespace WsSeguUta.AuthSystem.API.Middleware
{
  public class ErrorHandlerMiddleware
  {
    private readonly RequestDelegate _next; private readonly ILogger<ErrorHandlerMiddleware> _logger;
    public ErrorHandlerMiddleware(RequestDelegate next, ILogger<ErrorHandlerMiddleware> logger){ _next=next; _logger=logger; }
    public async Task Invoke(HttpContext context){ try{ await _next(context);} catch(Exception ex){ _logger.LogError(ex,"Unhandled"); context.Response.StatusCode=(int)HttpStatusCode.InternalServerError; context.Response.ContentType="application/json"; var body = JsonSerializer.Serialize(new { success=false, message="Error interno", errors=new[]{ ex.Message }, timestamp=DateTime.UtcNow }); await context.Response.WriteAsync(body);} }
  }
}
