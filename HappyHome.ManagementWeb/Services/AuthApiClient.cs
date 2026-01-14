using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace HappyHome.ManagementWeb.Services
{
    public class AuthApiClient : IAuthApiClient
    {
        private readonly HttpClient _http;

        public AuthApiClient(HttpClient http)
        {
            _http = http;
        }

        public async Task<TokenResponseDto> LoginAsync(LoginRequestDto dto, CancellationToken ct = default)
        {
            var res = await _http.PostAsJsonAsync("api/auth/login", dto, ct);
            if (!res.IsSuccessStatusCode) throw new UnauthorizedAccessException("Login failed");

            return (await res.Content.ReadFromJsonAsync<TokenResponseDto>(cancellationToken: ct))!;
        }

        public async Task<TokenResponseDto> RefreshAsync(RefreshRequestDto dto, CancellationToken ct = default)
        {
            var res = await _http.PostAsJsonAsync("api/auth/refresh", dto, ct);
            if (!res.IsSuccessStatusCode) throw new UnauthorizedAccessException("Refresh failed");

            return (await res.Content.ReadFromJsonAsync<TokenResponseDto>(cancellationToken: ct))!;
        }

        public async Task LogoutAsync(RefreshRequestDto dto, CancellationToken ct = default)
        {
            // API logout is AllowAnonymous; no bearer needed
            var res = await _http.PostAsJsonAsync("api/auth/logout", dto, ct);
            // even if fails, we still clear local session
        }

        public async Task<MeResponseDto> MeAsync(string accessToken, CancellationToken ct = default)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "api/auth/me");
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var res = await _http.SendAsync(req, ct);
            if (!res.IsSuccessStatusCode) throw new UnauthorizedAccessException("Me failed");

            return (await res.Content.ReadFromJsonAsync<MeResponseDto>(cancellationToken: ct))!;
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequestDto dto)
        {
            var res = await _http.PostAsJsonAsync("/api/auth/forgot-password", dto);
            res.EnsureSuccessStatusCode();
        }

        public async Task ResetPasswordAsync(ResetPasswordRequestDto dto)
        {
            var res = await _http.PostAsJsonAsync("/api/auth/reset-password", dto);

            if (res.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                throw new UnauthorizedAccessException();

            res.EnsureSuccessStatusCode(); // expect 204
        }
    }
}
