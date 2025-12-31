using HappyHome.ManagementWeb.Auth;
using HappyHome.ManagementWeb.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace HappyHome.ManagementWeb.Controllers
{
    public class AuthController : Controller
    {
        private readonly IAuthApiClient _authApi;
        private readonly IAuthSessionStore _store;

        public AuthController(IAuthApiClient authApi, IAuthSessionStore store)
        {
            _authApi = authApi;
            _store = store;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string? returnUrl = null)
        {
            if (User?.Identity?.IsAuthenticated == true)
                return RedirectToAction("Index", "Home");

            // Default: về Home nếu không có returnUrl
            if (string.IsNullOrWhiteSpace(returnUrl))
                returnUrl = Url.Content("~/");

            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string username, string password, string? returnUrl = null)
        {
            try
            {
                var token = await _authApi.LoginAsync(new LoginRequestDto
                {
                    Username = username,
                    Password = password
                });

                // store tokens in session
                _store.Set(new AuthSession
                {
                    AccessToken = token.AccessToken,
                    RefreshToken = token.RefreshToken,
                    AccessTokenExpiresAtUtc = DateTime.UtcNow.AddSeconds(token.ExpiresIn)
                });

                // get profile + roles
                var me = await _authApi.MeAsync(token.AccessToken);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, me.UserId),
                    new Claim(ClaimTypes.Name, me.Username)
                };
                foreach (var r in me.Roles)
                    claims.Add(new Claim(ClaimTypes.Role, r));

                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties { IsPersistent = true });

                if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
                    return Redirect(returnUrl);

                return RedirectToAction("Index", "Home");
            }
            catch
            {
                ModelState.AddModelError("", "Login failed");
                ViewBag.ReturnUrl = returnUrl;
                return View();
            }
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var session = _store.Get();
            if (session != null && !string.IsNullOrWhiteSpace(session.RefreshToken))
            {
                await _authApi.LogoutAsync(new RefreshRequestDto { RefreshToken = session.RefreshToken });
            }

            _store.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult AccessDenied() => View();
    }
}
