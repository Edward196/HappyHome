using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using HappyHome.Application.Auth.Abstractions;
using HappyHome.Application.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace HappyHome.Infrastructure.Security;

public class TokenService : ITokenService
{
    private readonly JwtOptions _jwt;
    private readonly UserManager<IdentityUser> _userManager;

    public TokenService(IOptions<JwtOptions> jwtOptions, UserManager<IdentityUser> userManager)
    {
        _jwt = jwtOptions.Value;
        _userManager = userManager;
    }

    public async Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new UnauthorizedAccessException("User not found");

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
