namespace HappyHome.ManagementWeb.Models;
using System.Net;
using System.Net.Http.Headers;

public class ApiAuthHandler : DelegatingHandler
{
    private readonly IApiTokenStore _tokenStore;
    private readonly IAuthApiClient _authClient; // client riêng cho auth/refresh
    private readonly IHttpContextAccessor _http;

    public ApiAuthHandler(IApiTokenStore tokenStore, IAuthApiClient authClient, IHttpContextAccessor http)
    {
        _tokenStore = tokenStore;
        _authClient = authClient;
        _http = http;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var tokens = _tokenStore.Get();
        if (tokens is null)
            return await base.SendAsync(request, ct);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var response = await base.SendAsync(request, ct);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
            return response;

        // Try refresh once
        var refreshed = await TryRefreshAsync(tokens, ct);
        if (!refreshed)
        {
            // logout UI cookie if refresh fails
            _tokenStore.Clear();
            // optional: sign out cookie
            // await _http.HttpContext!.SignOutAsync("Cookies");
            return response;
        }

        // Retry original request with new token
        response.Dispose();
        var retry = await CloneHttpRequestMessageAsync(request);
        var newTokens = _tokenStore.Get()!;
        retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newTokens.AccessToken);
        return await base.SendAsync(retry, ct);
    }

    private async Task<bool> TryRefreshAsync(ApiTokens current, CancellationToken ct)
    {
        try
        {
            var resp = await _authClient.RefreshAsync(new RefreshRequest(current.RefreshToken), ct);

            var newTokens = new ApiTokens
            {
                AccessToken = resp.AccessToken,
                AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(resp.ExpiresInSeconds - 30), // safety buffer
                RefreshToken = resp.RefreshToken
            };

            _tokenStore.Set(newTokens);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<HttpRequestMessage> CloneHttpRequestMessageAsync(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri);

        // Copy headers
        foreach (var header in request.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        // Copy content (if any)
        if (request.Content != null)
        {
            var ms = new MemoryStream();
            await request.Content.CopyToAsync(ms);
            ms.Position = 0;
            clone.Content = new StreamContent(ms);

            foreach (var header in request.Content.Headers)
                clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        return clone;
    }
}

