using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text.Json;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;
using WsSeguUta.AuthSystem.API.Utilities;

namespace WsSeguUta.AuthSystem.API.Controllers;
[ApiController]
[Route("api/menu")]
[Authorize]
public class MenuController : ControllerBase
{
  private readonly IMenuService _menu;
  private readonly IUserActivityService _activity;
  public MenuController(IMenuService menu, IUserActivityService activity){_menu=menu;_activity=activity;}

  [HttpGet("user")]
  public async Task<IActionResult> GetByUser(){
    var sub=User.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier);
    if(!Guid.TryParse(sub,out var userId)) return Unauthorized(ApiResponse.Fail("Token inválido"));
    Guid? sessionId = Guid.TryParse(User.FindFirstValue("sid"), out var sid) ? sid : null;
    IEnumerable<object> items;
    try
    {
      items=await _menu.GetMenuForUserAsync(userId);
    }
    catch (Exception ex)
    {
      await _activity.LogAsync(userId, UserActivityCodes.MenuLoadError, new { error = ex.GetType().Name },
        sessionId, ClientRequestInfo.GetClientIp(HttpContext), ClientRequestInfo.GetUserAgent(HttpContext));
      throw;
    }
    if (!items.Any())
    {
      var roles = User.FindAll(System.Security.Claims.ClaimTypes.Role).Select(c => c.Value).ToArray();
      await _activity.LogAsync(userId, UserActivityCodes.MenuLoadEmpty, new { roles },
        sessionId, ClientRequestInfo.GetClientIp(HttpContext), ClientRequestInfo.GetUserAgent(HttpContext));
    }
    //var json = JsonSerializer.Serialize(
    //    items,
    //    new JsonSerializerOptions
    //    {
    //        WriteIndented = true // bonito / legible
    //    }
    //);

    //Console.WriteLine("**************************** menu Extraido (JSON):");
    //Console.WriteLine(json);
    return Ok(ApiResponse.Ok(items));
  }
}
