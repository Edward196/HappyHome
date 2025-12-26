using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public class JwtOptions
{
    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";
    public string SigningKey { get; set; } = ""; // >= 32 chars recommended
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 14;
}

public interface IJwtTokenService
{
    Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(IdentityUser user);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtOptions _opt;

    public JwtTokenService(UserManager<IdentityUser> userManager, IOptions<JwtOptions> opt)
    {
        _userManager = userManager;
        _opt = opt.Value;
    }

    public async Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(IdentityUser user)
    {
        var roles = (await _userManager.GetRolesAsync(user)).ToArray();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.UniqueName, user.UserName ?? ""),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName ?? "")
        };

        foreach (var r in roles)
            claims.Add(new Claim(ClaimTypes.Role, r));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_opt.SigningKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expires = DateTime.UtcNow.AddMinutes(_opt.AccessTokenMinutes);

        var jwt = new JwtSecurityToken(
            issuer: _opt.Issuer,
            audience: _opt.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expires,
            signingCredentials: creds
        );

        var token = new JwtSecurityTokenHandler().WriteToken(jwt);
        var expiresInSeconds = (int)TimeSpan.FromMinutes(_opt.AccessTokenMinutes).TotalSeconds;

        return (token, expiresInSeconds, roles);
    }
}
