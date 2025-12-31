using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
namespace HappyHome.Api.Infrastructure.Contracts;

public class JwtOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;

    // minutes
    public int AccessTokenMinutes { get; set; } = 15;

    // days
    public int RefreshTokenDays { get; set; } = 14;
}

public interface IJwtTokenService
{
    /// <summary>
    /// Create JWT access token
    /// </summary>
    /// <returns>
    /// token, expiresInSeconds, roles
    /// </returns>
    Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(IdentityUser user);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly JwtOptions _jwt;
    private readonly UserManager<IdentityUser> _userManager;

    public JwtTokenService(
            IOptions<JwtOptions> jwtOptions,
            UserManager<IdentityUser> userManager)
    {
        _jwt = jwtOptions.Value;
        _userManager = userManager;
    }

    public async Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(IdentityUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            };

        foreach (var r in roles)
            claims.Add(new Claim(ClaimTypes.Role, r));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expires = DateTime.UtcNow.AddMinutes(_jwt.AccessTokenMinutes);

        var jwt = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds);

        var token = new JwtSecurityTokenHandler().WriteToken(jwt);
        var expiresInSeconds = (int)TimeSpan.FromMinutes(_jwt.AccessTokenMinutes).TotalSeconds;

        return (token, expiresInSeconds, roles.ToArray());
    }
}
