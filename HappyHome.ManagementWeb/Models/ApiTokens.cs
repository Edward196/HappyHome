namespace HappyHome.ManagementWeb.Models;

public class ApiTokens
{
    public string AccessToken { get; set; } = "";
    public DateTimeOffset AccessTokenExpiresAt { get; set; }
    public string RefreshToken { get; set; } = "";
}
