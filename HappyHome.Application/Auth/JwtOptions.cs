
namespace HappyHome.Application.Auth;

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