using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;

[ApiController]
[Route("api/notifications")]
[Authorize] // Requiere autenticación para gestionar notificaciones
public class NotificationController : ControllerBase
{
    private readonly INotificationService _notificationService;
    private readonly ILogger<NotificationController> _logger;

    public NotificationController(INotificationService notificationService, ILogger<NotificationController> logger)
    {
        _notificationService = notificationService;
        _logger = logger;
    }

    /// <summary>
    /// Crear una nueva suscripción de webhook para una aplicación
    /// </summary>
    /// <param name="request">Datos de la suscripción</param>
    /// <returns>ID de la suscripción creada</returns>
    [HttpPost("subscriptions")]
    public async Task<IActionResult> CreateSubscription([FromBody] CreateNotificationSubscriptionDto request)
    {
        try
        {
            _logger.LogInformation("Creating notification subscription for application {ApplicationId}", request.ApplicationId);
            
            var subscriptionId = await _notificationService.CreateSubscriptionAsync(
                request.ApplicationId, 
                request.EventType, 
                request.WebhookUrl, 
                request.SecretKey
            );
            
            return Ok(ApiResponse.Ok(new { SubscriptionId = subscriptionId }, "Subscription created successfully"));
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning("Invalid request for creating subscription: {Message}", ex.Message);
            return BadRequest(ApiResponse.Fail(ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating notification subscription");
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Actualizar una suscripción existente
    /// </summary>
    /// <param name="subscriptionId">ID de la suscripción</param>
    /// <param name="request">Datos a actualizar</param>
    /// <returns>Resultado de la actualización</returns>
    [HttpPut("subscriptions/{subscriptionId}")]
    public async Task<IActionResult> UpdateSubscription(Guid subscriptionId, [FromBody] UpdateNotificationSubscriptionDto request)
    {
        try
        {
            var success = await _notificationService.UpdateSubscriptionAsync(
                subscriptionId, 
                request.WebhookUrl, 
                request.SecretKey, 
                request.IsActive
            );
            
            if (success)
            {
                return Ok(ApiResponse.Ok(null, "Subscription updated successfully"));
            }
            else
            {
                return NotFound(ApiResponse.Fail("Subscription not found"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error updating notification subscription {SubscriptionId}", subscriptionId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Eliminar una suscripción
    /// </summary>
    /// <param name="subscriptionId">ID de la suscripción</param>
    /// <returns>Resultado de la eliminación</returns>
    [HttpDelete("subscriptions/{subscriptionId}")]
    public async Task<IActionResult> DeleteSubscription(Guid subscriptionId)
    {
        try
        {
            var success = await _notificationService.DeleteSubscriptionAsync(subscriptionId);
            
            if (success)
            {
                return Ok(ApiResponse.Ok(null, "Subscription deleted successfully"));
            }
            else
            {
                return NotFound(ApiResponse.Fail("Subscription not found"));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting notification subscription {SubscriptionId}", subscriptionId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Obtener suscripciones de una aplicación
    /// </summary>
    /// <param name="applicationId">ID de la aplicación</param>
    /// <returns>Lista de suscripciones</returns>
    [HttpGet("subscriptions/application/{applicationId}")]
    public async Task<IActionResult> GetSubscriptionsByApplication(Guid applicationId)
    {
        try
        {
            var subscriptions = await _notificationService.GetSubscriptionsByApplicationAsync(applicationId);
            return Ok(ApiResponse.Ok(subscriptions, "Subscriptions retrieved successfully"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving subscriptions for application {ApplicationId}", applicationId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Obtener estadísticas generales de notificaciones
    /// </summary>
    /// <returns>Estadísticas de notificaciones</returns>
    [HttpGet("stats")]
    public async Task<IActionResult> GetNotificationStats()
    {
        try
        {
            var stats = await _notificationService.GetNotificationStatsAsync();
            return Ok(ApiResponse.Ok(stats, "Notification statistics retrieved"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving notification statistics");
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Obtener estadísticas de suscripciones de una aplicación
    /// </summary>
    /// <param name="applicationId">ID de la aplicación</param>
    /// <returns>Estadísticas de suscripciones</returns>
    [HttpGet("stats/application/{applicationId}")]
    public async Task<IActionResult> GetSubscriptionStats(Guid applicationId)
    {
        try
        {
            var stats = await _notificationService.GetSubscriptionStatsAsync(applicationId);
            return Ok(ApiResponse.Ok(stats, "Subscription statistics retrieved"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving subscription statistics for application {ApplicationId}", applicationId);
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Procesar notificaciones pendientes manualmente (para administradores)
    /// </summary>
    /// <returns>Resultado del procesamiento</returns>
    [HttpPost("process-pending")]
    public async Task<IActionResult> ProcessPendingNotifications()
    {
        try
        {
            _logger.LogInformation("Manual processing of pending notifications requested");
            await _notificationService.ProcessPendingNotificationsAsync();
            return Ok(ApiResponse.Ok(null, "Pending notifications processed"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing pending notifications");
            return StatusCode(500, ApiResponse.Fail("Internal server error"));
        }
    }

    /// <summary>
    /// Endpoint de prueba para webhooks (para testing)
    /// </summary>
    /// <param name="payload">Payload del webhook</param>
    /// <returns>Confirmación de recepción</returns>
    [HttpPost("webhook-test")]
    [AllowAnonymous]
    public async Task<IActionResult> WebhookTest([FromBody] object payload)
    {
        try
        {
            _logger.LogInformation("Test webhook received: {Payload}", System.Text.Json.JsonSerializer.Serialize(payload));
            
            // Simular procesamiento
            await Task.Delay(100);
            
            return Ok(new { 
                Status = "Success", 
                Message = "Webhook received successfully", 
                Timestamp = DateTime.Now,
                ReceivedPayload = payload 
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in test webhook");
            return StatusCode(500, new { Status = "Error", Message = "Internal server error" });
        }
    }
}

