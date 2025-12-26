using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using HappyHome.ManagementWeb.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity.Data;

namespace HappyHome.ManagementWeb.Controllers;

public class AuthController : Controller
{
    private readonly IAuthApiClient _auth;
    private readonly IApiTokenStore _tokenStore;

    public AuthController(IAuthApiClient auth, IApiTokenStore tokenStore)
    {
        _auth = auth;
        _tokenStore = tokenStore;
    }

    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        var resp = await _auth.LoginAsync(new LoginRequest(username, password));

        _tokenStore.Set(new ApiTokens
        {
            AccessToken = resp.AccessToken,
            AccessTokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(resp.ExpiresInSeconds - 30),
            RefreshToken = resp.RefreshToken
        });

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, resp.UserId.ToString()),
            new Claim(ClaimTypes.Name, resp.UserName),
        };
        foreach (var r in resp.Roles) claims.Add(new Claim(ClaimTypes.Role, r));

        await HttpContext.SignInAsync("Cookies", new ClaimsPrincipal(new ClaimsIdentity(claims, "Cookies")));
        return RedirectToAction("Index", "Dashboard");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        // optional: call API logout to revoke refresh token
        var tokens = _tokenStore.Get();
        if (tokens != null)
            await _auth.LogoutAsync(new RefreshRequest(tokens.RefreshToken));

        _tokenStore.Clear();
        await HttpContext.SignOutAsync("Cookies");
        return RedirectToAction("Login");
    }
}
