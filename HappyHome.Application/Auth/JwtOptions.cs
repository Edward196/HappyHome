
namespace HappyHome.Application.Auth;

public class JwtOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;

    // Tokens
    public int AccessTokenMinutes { get; set; }
    public int RefreshTokenDays { get; set; }

    // Reset Password
    public string ResetPasswordUrlTemplate { get; set; } = string.Empty;
    public string MailFrom { get; set; } = string.Empty;
}