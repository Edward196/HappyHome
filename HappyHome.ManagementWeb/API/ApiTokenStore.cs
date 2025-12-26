using System.Text.Json;
using HappyHome.ManagementWeb.Models;

public interface IApiTokenStore
{
    ApiTokens? Get();
    void Set(ApiTokens tokens);
    void Clear();
}

public class SessionApiTokenStore : IApiTokenStore
{
    private const string Key = "API_TOKENS";
    private readonly IHttpContextAccessor _http;

    public SessionApiTokenStore(IHttpContextAccessor http) => _http = http;

    public ApiTokens? Get()
    {
        var json = _http.HttpContext?.Session.GetString(Key);
        return string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<ApiTokens>(json);
    }

    public void Set(ApiTokens tokens)
    {
        var json = JsonSerializer.Serialize(tokens);
        _http.HttpContext!.Session.SetString(Key, json);
    }

    public void Clear() => _http.HttpContext!.Session.Remove(Key);
}
