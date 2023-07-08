using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using IdentityServerSample.Api.Data.Entities;
using IdentityServerSample.Api.Models;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServerSample.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly IConfigurationSection _jwtSettings;
    private readonly UserManager<User> _userManager;

    public AccountController(IConfiguration configuration, UserManager<User> userManager)
    {
        _userManager = userManager;
        _jwtSettings = configuration.GetSection("JwtSettings");
    }

    /// <summary>
    /// Register a user
    /// </summary>
    /// <param name="userModel"></param>
    /// <returns></returns>
    [HttpPost("Register")]
    public async Task<ActionResult> Register(UserRegistrationModel userModel)
    {
        var user = userModel.Adapt<User>();
        var result = await _userManager.CreateAsync(user, userModel.Password);
        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        await _userManager.AddToRoleAsync(user, "Visitor");
        return StatusCode((int)HttpStatusCode.Created);
    }

    [HttpPost("login")]
    public async Task<ActionResult> login(UserLoginModel userLoginModel)
    {
        var user = await _userManager.FindByEmailAsync(userLoginModel.Email);
        if (user == null)
        {
            return Unauthorized("Invalid Credentials");
        }

        var isCorrectPassword = await _userManager.CheckPasswordAsync(user, userLoginModel.Password);
        if (!isCorrectPassword)
        {
            return Unauthorized("Invalid Credentials");
        }

        var signingCredentials = GetSigningCredentials();
        var claims = await GetClaims(user);
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        return Ok(token);
    }


    private SigningCredentials GetSigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(_jwtSettings.GetSection("securityKey").Value);
        var secret = new SymmetricSecurityKey(key);
        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
    {
        var tokenOptions = new JwtSecurityToken(
            issuer: _jwtSettings.GetSection("validIssuer").Value,
            audience: _jwtSettings.GetSection("validAudience").Value,
            claims: claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble(_jwtSettings.GetSection("expiryInMinutes").Value)),
            signingCredentials: signingCredentials);
        return tokenOptions;
    }

    private async Task<List<Claim>> GetClaims(User user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.Email)
        };
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        return claims;
    }
}