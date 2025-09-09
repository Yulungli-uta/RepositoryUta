﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using WsSeguUta.AuthSystem.API.Models.DTOs;
using WsSeguUta.AuthSystem.API.Services.Interfaces;

namespace WsSeguUta.AuthSystem.API.Controllers;
[ApiController]
[Route("api/menu")]
[Authorize]
public class MenuController : ControllerBase
{
  private readonly IMenuService _menu; public MenuController(IMenuService menu)=>_menu=menu;

  [HttpGet("user")]
  public async Task<IActionResult> GetByUser(){
    var sub=User.FindFirstValue(System.Security.Claims.ClaimTypes.NameIdentifier);
    if(!Guid.TryParse(sub,out var userId)) return Unauthorized(ApiResponse.Fail("Token inválido"));
    var items=await _menu.GetMenuForUserAsync(userId);
    return Ok(ApiResponse.Ok(items));
  }
}
