using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace HappyHome.ManagementWeb.Auth
{
    public class SessionAuthSessionStore : IAuthSessionStore
    {
        private const string KEY = "HH_AUTH_SESSION";
        private readonly IHttpContextAccessor _http;

        public SessionAuthSessionStore(IHttpContextAccessor http)
        {
            _http = http;
        }

        public AuthSession? Get()
        {
            var ctx = _http.HttpContext;
            if (ctx == null) return null;

            var json = ctx.Session.GetString(KEY);
            if (string.IsNullOrWhiteSpace(json)) return null;

            return JsonSerializer.Deserialize<AuthSession>(json);
        }

        public void Set(AuthSession session)
        {
            var ctx = _http.HttpContext ?? throw new InvalidOperationException("No HttpContext");
            var json = JsonSerializer.Serialize(session);
            ctx.Session.SetString(KEY, json);
        }

        public void Clear()
        {
            var ctx = _http.HttpContext;
            ctx?.Session.Remove(KEY);
        }
    }
}
