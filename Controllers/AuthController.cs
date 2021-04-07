using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using JwtExample.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace JwtExample.Controllers
{
  [ApiController]
  [Route("api/auth")]
  public class AuthController : ControllerBase
  {
    [HttpGet]
    [Route("GenerateToken")]
    public IActionResult GetToken()
    {
      var tokenService = new TokenService();

      var token = tokenService.GenerateToken();

      var response = new
      {
        Token = token
      };

      return Ok(response);
    }

    [HttpGet]
    [Route("ValidateToken/{token}")]
    public IActionResult ValidateToken([FromRoute] string token)
    {
      var tokenService = new TokenService();

      if (tokenService.ValidateToken(token))
        return Ok(new { Message = "OK" });

      return BadRequest(new { Message = "Invalid Token." });
    }

    [HttpGet]
    [Route("DecodeToken/{token}")]
    public IActionResult DecodeToken([FromRoute] string token)
    {
      var tokenService = new TokenService();

      if (!tokenService.ValidateToken(token))
        return BadRequest(new { Message = "Invalid Token." });

      try
      {
        var decodedToken = tokenService.DecodeToken<TokenPayload>(token);

        return Ok(decodedToken);
      }
      catch (Exception exception)
      {
        return BadRequest(new { Message = exception.Message });
      }
    }
  }
}
