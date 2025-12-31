namespace HappyHome.ManagementWeb.Auth
{
    public class AuthSession
    {
        public string AccessToken { get; set; } = "";
        public string RefreshToken { get; set; } = "";
        public DateTime AccessTokenExpiresAtUtc { get; set; } // optional
    }
}