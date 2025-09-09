using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Claims;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;
[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
  private readonly IAuthService _auth;
  private readonly IAzureAuthService _azure;
  public AuthController(IAuthService auth, IAzureAuthService azure){ _auth=auth; _azure=azure; }

  [HttpPost("login")][AllowAnonymous][EnableRateLimiting("login")]
  public async Task<IActionResult> Login([FromBody] LoginRequest req){
    Console.WriteLine($"Login attempt for {req.Email}");
    var pair=await _auth.LoginLocalAsync(req.Email,req.Password);
    return pair is null ? Unauthorized(ApiResponse.Fail("Credenciales inválidas")) : Ok(ApiResponse.Ok(pair,"Login exitoso"));
  }

  [HttpPost("refresh")][AllowAnonymous]
  public async Task<IActionResult> Refresh([FromBody] RefreshRequest req){
    var pair=await _auth.RefreshAsync(req.RefreshToken);
    return pair is null ? Unauthorized(ApiResponse.Fail("Refresh token invÃ¡lido")) : Ok(ApiResponse.Ok(pair));
  }

  [HttpGet("azure/url")][AllowAnonymous]
  public async Task<IActionResult> AzureUrl(){ 
        var (url,state)=await _azure.BuildAuthUrlAsync(); 
        Console.WriteLine($"Azure auth URL generated: {url} with state {state}");
        return Ok(ApiResponse.Ok(new { url, state })); }

  [HttpGet("azure/callback")][AllowAnonymous]
  public async Task<IActionResult> AzureCallback([FromQuery] string code,[FromQuery] string state){
        Console.WriteLine($"Azure callback received. Code: {code}, State: {state}");
        var pair=await _azure.HandleCallbackAsync(code,state);
    return pair is null ? Unauthorized(ApiResponse.Fail("No autorizado")) : Ok(ApiResponse.Ok(pair));
  }

  [HttpGet("me")][Authorize]
  public async Task<IActionResult> Me(){
    Console.WriteLine($"Fetching current user info { ClaimTypes.NameIdentifier}");
    var sub=User.FindFirstValue(ClaimTypes.NameIdentifier);
    Console.WriteLine($"valor Recuperado: {sub}");
    if(!Guid.TryParse(sub,out var id)) return Unauthorized(ApiResponse.Fail("Token inválido"));
    var me=await _auth.MeAsync(id);
    return me is null ? NotFound(ApiResponse.Fail("Usuario no encontrado")) : Ok(ApiResponse.Ok(me));
  }
}
