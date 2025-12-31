using System.Text.Json.Serialization;

namespace HappyHome.ManagementWeb.Services
{
    public class LoginRequestDto
    {
        [JsonPropertyName("username")]
        public string Username { get; set; } = "";

        [JsonPropertyName("password")]
        public string Password { get; set; } = "";
    }

    public class RefreshRequestDto
    {
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = "";
    }

    public class TokenResponseDto
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = "";

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; } // seconds

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; } = "";
    }

    public class MeResponseDto
    {
        [JsonPropertyName("user_id")]
        public string UserId { get; set; } = "";

        [JsonPropertyName("username")]
        public string Username { get; set; } = "";

        [JsonPropertyName("roles")]
        public List<string> Roles { get; set; } = new();
    }
}
