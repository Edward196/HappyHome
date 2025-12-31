namespace HappyHome.ManagementWeb.Services
{
    public class BackendApiClient : IBackendApiClient
    {
        private readonly HttpClient _http;
        public BackendApiClient(HttpClient http) => _http = http;

        public async Task<string> PingAsync(CancellationToken ct = default)
        {
            // ví dụ endpoint protected nào đó của bạn
            var res = await _http.GetAsync("api/auth/me", ct);
            return await res.Content.ReadAsStringAsync(ct);
        }
    }
}
