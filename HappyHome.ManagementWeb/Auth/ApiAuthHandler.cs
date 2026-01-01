using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using HappyHome.ManagementWeb.Services;

namespace HappyHome.ManagementWeb.Auth
{
    public class ApiAuthHandler : DelegatingHandler
    {
        private static readonly SemaphoreSlim _refreshLock = new(1, 1);

        private readonly IAuthSessionStore _store;
        private readonly IAuthApiClient _authApi;

        public ApiAuthHandler(IAuthSessionStore store, IAuthApiClient authApi)
        {
            _store = store;
            _authApi = authApi;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var session = _store.Get();
            if (session == null || string.IsNullOrWhiteSpace(session.AccessToken))
            {
                // No token -> let API return 401; MVC can handle redirect
                return await base.SendAsync(request, cancellationToken);
            }

            // attach bearer
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", session.AccessToken);

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode != HttpStatusCode.Unauthorized)
                return response;

            // Try refresh once
            response.Dispose();

            await _refreshLock.WaitAsync(cancellationToken);
            try
            {
                // session might have been refreshed by another request
                session = _store.Get();
                if (session == null || string.IsNullOrWhiteSpace(session.RefreshToken))
                    return new HttpResponseMessage(HttpStatusCode.Unauthorized);

                // refresh
                var tokenRes = await _authApi.RefreshAsync(new RefreshRequestDto
                {
                    RefreshToken = session.RefreshToken
                }, cancellationToken);

                var newSession = new AuthSession
                {
                    AccessToken = tokenRes.AccessToken,
                    RefreshToken = tokenRes.RefreshToken,
                    AccessTokenExpiresAtUtc = DateTime.UtcNow.AddSeconds(tokenRes.ExpiresIn)
                };
                _store.Set(newSession);
            }
            catch
            {
                _store.Clear();
                return new HttpResponseMessage(HttpStatusCode.Unauthorized);
            }
            finally
            {
                _refreshLock.Release();
            }

            // retry original request with new token
            var retry = await CloneHttpRequestMessageAsync(request, cancellationToken);
            var latest = _store.Get();
            if (latest != null)
                retry.Headers.Authorization = new AuthenticationHeaderValue("Bearer", latest.AccessToken);

            return await base.SendAsync(retry, cancellationToken);
        }

        private static async Task<HttpRequestMessage> CloneHttpRequestMessageAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var clone = new HttpRequestMessage(request.Method, request.RequestUri);

            // copy headers except Authorization (we will set it)
            foreach (var header in request.Headers)
            {
                if (string.Equals(header.Key, "Authorization", StringComparison.OrdinalIgnoreCase))
                    continue;
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            // copy content
            if (request.Content != null)
            {
                var ms = new MemoryStream();
                await request.Content.CopyToAsync(ms, ct);
                ms.Position = 0;
                clone.Content = new StreamContent(ms);

                foreach (var h in request.Content.Headers)
                    clone.Content.Headers.TryAddWithoutValidation(h.Key, h.Value);
            }

            return clone;
        }
    }
}
