using HappyHome.Application.Auth.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using HappyHome.Application.Auth;

namespace HappyHome.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _auth;

        public AuthController(IAuthService auth) => _auth = auth;

        [HttpPost("login")]
        [AllowAnonymous]
        public Task<TokenResponseDto> Login(LoginRequestDto dto) => _auth.LoginAsync(dto);

        [HttpPost("refresh")]
        [AllowAnonymous]
        public Task<TokenResponseDto> Refresh(RefreshRequestDto dto) => _auth.RefreshAsync(dto);

        [HttpPost("logout")]
        [AllowAnonymous]
        public async Task<IActionResult> Logout(RefreshRequestDto dto)
        {
            await _auth.LogoutAsync(dto);
            return NoContent();
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<MeResponseDto>> Me()
        {
            var userId = User.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value
                         ?? User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

            if (string.IsNullOrWhiteSpace(userId))
                return Unauthorized();

            try
            {
                var me = await _auth.MeAsync(userId);
                return Ok(me);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequestDto dto)
        {
            await _auth.ForgotPasswordAsync(dto);
            return Ok(); // always OK to avoid user enumeration
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequestDto dto)
        {
            try
            {
                await _auth.ResetPasswordAsync(dto);
                return NoContent();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }
    }
}
