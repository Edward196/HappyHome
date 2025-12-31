using HappyHome.Api.Infrastructure.Contracts;
using HappyHome.Api.Database;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HappyHome.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IJwtTokenService _jwtTokenService;
        private readonly ITokenCrypto _crypto;
        private readonly JwtOptions _jwt;

        public AuthController(
            ApplicationDbContext db,
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            IJwtTokenService jwtTokenService,
            ITokenCrypto crypto,
            Microsoft.Extensions.Options.IOptions<JwtOptions> jwtOptions)
        {
            _db = db;
            _userManager = userManager;
            _signInManager = signInManager;
            _jwtTokenService = jwtTokenService;
            _crypto = crypto;
            _jwt = jwtOptions.Value;
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<ActionResult<TokenResponseDto>> Login([FromBody] LoginRequestDto dto)
        {
            var user = await _userManager.FindByNameAsync(dto.Username);
            if (user == null)
                return Unauthorized();

            var signIn = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);
            if (!signIn.Succeeded)
                return Unauthorized();

            var (token, expiresIn, roles) = await _jwtTokenService.CreateAccessTokenAsync(user);

            var refreshTokenPlain = _crypto.GenerateSecureToken();
            var refreshTokenHash = _crypto.HashToken(refreshTokenPlain);

            _db.RefreshTokens.Add(new Infrastructure.Identity.RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = user.Id,
                TokenHash = refreshTokenHash,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays)
            });

            await _db.SaveChangesAsync();

            return Ok(new TokenResponseDto
            {
                AccessToken = token,
                ExpiresIn = expiresIn,
                RefreshToken = refreshTokenPlain
            });
        }

        [HttpPost("refresh")]
        [AllowAnonymous]
        public async Task<ActionResult<TokenResponseDto>> Refresh([FromBody] RefreshRequestDto dto)
        {
            var hash = _crypto.HashToken(dto.RefreshToken);

            var rt = await _db.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == hash);
            if (rt == null)
                return Unauthorized();

            if (rt.RevokedAtUtc != null)
                return Unauthorized();

            if (rt.ExpiresAtUtc <= DateTime.UtcNow)
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(rt.UserId);
            if (user == null)
                return Unauthorized();

            // ✅ rotate
            rt.RevokedAtUtc = DateTime.UtcNow;

            var newRefreshPlain = _crypto.GenerateSecureToken();
            var newHash = _crypto.HashToken(newRefreshPlain);
            rt.ReplacedByTokenHash = newHash;

            _db.RefreshTokens.Add(new Infrastructure.Identity.RefreshToken
            {
                Id = Guid.NewGuid(),
                UserId = rt.UserId,
                TokenHash = newHash,
                CreatedAtUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays)
            });

            await _db.SaveChangesAsync();

            var (token, expiresIn, roles) = await _jwtTokenService.CreateAccessTokenAsync(user);

            return Ok(new TokenResponseDto
            {
                AccessToken = token,
                ExpiresIn = expiresIn,
                RefreshToken = newRefreshPlain
            });
        }

        // allow logout even if access token expired (logout uses refresh token)
        [HttpPost("logout")]
        [AllowAnonymous]
        public async Task<IActionResult> Logout([FromBody] RefreshRequestDto dto)
        {
            var hash = _crypto.HashToken(dto.RefreshToken);

            var rt = await _db.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == hash);
            if (rt == null)
                return NoContent();

            if (rt.RevokedAtUtc == null)
            {
                rt.RevokedAtUtc = DateTime.UtcNow;
                await _db.SaveChangesAsync();
            }

            return NoContent();
        }

        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<MeResponseDto>> Me()
        {
            var userId = _userManager.GetUserId(User);
            if (string.IsNullOrWhiteSpace(userId))
                return Unauthorized();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized();

            var roles = await _userManager.GetRolesAsync(user);

            return Ok(new MeResponseDto
            {
                UserId = user.Id,
                Username = user.UserName ?? "",
                Roles = roles.ToList()
            });
        }
    }
}
