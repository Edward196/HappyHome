public interface IHappyHomeApiClient
{
    Task<LoginResponse> LoginAsync(LoginRequest req);
    Task<List<OrderDto>> GetOrdersAsync();
}

public class HappyHomeApiClient : IHappyHomeApiClient
{
    private readonly HttpClient _http;
    private readonly IApiTokenStore _tokenStore;

    public HappyHomeApiClient(HttpClient http, IApiTokenStore tokenStore)
    {
        _http = http;
        _tokenStore = tokenStore;
    }

    private void AttachToken()
    {
        var token = _tokenStore.GetAccessToken();
        _http.DefaultRequestHeaders.Authorization =
            token is null ? null : new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
    }

    public async Task<LoginResponse> LoginAsync(LoginRequest req)
    {
        var res = await _http.PostAsJsonAsync("api/auth/login", req);
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<LoginResponse>())!;
    }

    public async Task<List<OrderDto>> GetOrdersAsync()
    {
        AttachToken();
        var res = await _http.GetAsync("api/orders");
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<List<OrderDto>>())!;
    }
}
