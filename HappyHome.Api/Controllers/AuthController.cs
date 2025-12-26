using HappyHome.API.Contracts;
using HappyHome.API.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly ApplicationDbContext _db;
    private readonly IJwtTokenService _jwt;
    private readonly JwtOptions _opt;

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        ApplicationDbContext db,
        IJwtTokenService jwt,
        IOptions<JwtOptions> opt)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _db = db;
        _jwt = jwt;
        _opt = opt.Value;
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(LoginRequest req)
    {
        var user = await _userManager.FindByNameAsync(req.Username)
                   ?? await _userManager.FindByEmailAsync(req.Username);

        if (user is null) return Unauthorized("Invalid credentials");

        var signIn = await _signInManager.CheckPasswordSignInAsync(user, req.Password, lockoutOnFailure: true);
        if (!signIn.Succeeded) return Unauthorized("Invalid credentials");

        var (accessToken, expiresIn, roles) = await _jwt.CreateAccessTokenAsync(user);

        // Create refresh token (store hash)
        var refresh = TokenCrypto.GenerateRefreshToken();
        var refreshHash = TokenCrypto.Sha256(refresh);

        var rt = new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshHash,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_opt.RefreshTokenDays),
        };

        _db.RefreshTokens.Add(rt);
        await _db.SaveChangesAsync();

        return new TokenResponse(
            AccessToken: accessToken,
            ExpiresInSeconds: expiresIn,
            RefreshToken: refresh,
            TokenType: "Bearer",
            UserName: user.UserName ?? "",
            UserId: user.Id,
            Roles: roles
        );
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(RefreshRequest req)
    {
        var incomingHash = TokenCrypto.Sha256(req.RefreshToken);

        var existing = await _db.RefreshTokens
            .AsTracking()
            .FirstOrDefaultAsync(x => x.TokenHash == incomingHash);

        if (existing is null || !existing.IsActive)
            return Unauthorized("Invalid refresh token");

        var user = await _userManager.FindByIdAsync(existing.UserId);
        if (user is null) return Unauthorized("User not found");

        // Rotate refresh token
        var newRefresh = TokenCrypto.GenerateRefreshToken();
        var newHash = TokenCrypto.Sha256(newRefresh);

        existing.RevokedAtUtc = DateTime.UtcNow;
        existing.ReplacedByTokenHash = newHash;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = newHash,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_opt.RefreshTokenDays),
        });

        var (accessToken, expiresIn, roles) = await _jwt.CreateAccessTokenAsync(user);

        await _db.SaveChangesAsync();

        return new TokenResponse(
            AccessToken: accessToken,
            ExpiresInSeconds: expiresIn,
            RefreshToken: newRefresh,
            TokenType: "Bearer",
            UserName: user.UserName ?? "",
            UserId: user.Id,
            Roles: roles
        );
    }

    // Optional: revoke current refresh token
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(RefreshRequest req)
    {
        var hash = TokenCrypto.Sha256(req.RefreshToken);
        var token = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.TokenHash == hash);
        if (token is null) return Ok();

        token.RevokedAtUtc = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return Ok();
    }
}
