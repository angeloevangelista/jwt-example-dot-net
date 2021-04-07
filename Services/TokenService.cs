using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace JwtExample.Services
{
  public class TokenService
  {
    private readonly string _secret = "418 - I'm a teapot";
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public TokenService()
    {
      _tokenHandler = new JwtSecurityTokenHandler();
    }

    public string GenerateToken()
    {
      var signingCredentials = new SigningCredentials(
        new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secret)),
        SecurityAlgorithms.HmacSha256
      );

      var tokenDescriptor = new SecurityTokenDescriptor
      {
        Subject = new ClaimsIdentity(new[]
        {
          new Claim("Username", "Angelo"),
          new Claim("Id", (new Random().Next(1000)).ToString() )
        }),

        Issuer = "self",
        Expires = DateTime.UtcNow.AddMinutes(60),
        SigningCredentials = signingCredentials,
      };

      var securityToken = _tokenHandler.CreateToken(tokenDescriptor);

      return _tokenHandler.WriteToken(securityToken);
    }

    public bool ValidateToken(string token)
    {
      var key = Encoding.ASCII.GetBytes(_secret);

      try
      {
        _tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
          ValidateIssuerSigningKey = true,
          IssuerSigningKey = new SymmetricSecurityKey(key),
          ValidateIssuer = false,
          ValidateAudience = false,
          ClockSkew = TimeSpan.Zero
        }, out SecurityToken validatedToken);

        var jwtToken = (JwtSecurityToken)validatedToken;

        return true;
      }
      catch
      {
        return false;
      }
    }

    public T DecodeToken<T>(string token)
    {
      var key = Encoding.ASCII.GetBytes(_secret);

      var decodedToken = _tokenHandler.ReadJwtToken(token);

      return JsonConvert.DeserializeObject<T>(decodedToken.Payload.SerializeToJson());
    }
  }
}