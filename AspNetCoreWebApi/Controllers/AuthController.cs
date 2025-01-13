using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AspNetCoreWebApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private int refreshTokenLifetimeDays = 7;
        private int tokenLifetimeMinutes = 30;

        public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;

            int.TryParse(_configuration["Jwt:RefreshTokenLifetimeDays"], out refreshTokenLifetimeDays);
            int.TryParse(_configuration["Jwt:AccessTokenLifetimeMinutes"], out tokenLifetimeMinutes);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok(new { message = "User registered successfully" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized();

            var accessToken = GenerateJwtToken(user.UserName);
            var refreshToken = Guid.NewGuid().ToString();

            user.SecurityStamp = refreshToken;
            user.LockoutEnd = DateTime.UtcNow.AddDays(tokenLifetimeMinutes);
            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                token = accessToken,
                refreshToken = refreshToken,
                refreshTokenExpiry = user.LockoutEnd
            });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || user.SecurityStamp != model.RefreshToken)
                return Unauthorized(new { message = "Invalid refresh token" });

            // Sprawdzenie daty wygaśnięcia refresh tokena
            if (user.LockoutEnd.HasValue && user.LockoutEnd < DateTime.UtcNow)
                return Unauthorized(new { message = "Refresh token expired" });

            var newAccessToken = GenerateJwtToken(user.UserName);
            var newRefreshToken = Guid.NewGuid().ToString();

            user.SecurityStamp = newRefreshToken;

            user.LockoutEnd = DateTime.UtcNow.AddDays(refreshTokenLifetimeDays);
            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                token = newAccessToken,
                refreshToken = newRefreshToken,
                refreshTokenExpiry = user.LockoutEnd
            });
        }

        private string GenerateJwtToken(string username)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(tokenLifetimeMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class RefreshTokenModel
    {
        public string Username { get; set; }
        public string RefreshToken { get; set; }
    }
}
