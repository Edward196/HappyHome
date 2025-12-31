using HappyHome.ManagementWeb.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using HappyHome.ManagementWeb.Auth;
using HappyHome.ManagementWeb.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Session (server-side)
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// Cookie auth for UI
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Auth/Login";
        options.LogoutPath = "/Auth/Logout";
        options.AccessDeniedPath = "/Auth/AccessDenied";
        options.ReturnUrlParameter = "returnUrl";
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);

        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    });
builder.Services.AddAuthorization();

// AuthSession store (Session)
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IAuthSessionStore, SessionAuthSessionStore>();

// Handler attach bearer + refresh + retry
builder.Services.AddScoped<ApiAuthHandler>();

// Typed API clients
builder.Services.AddHttpClient<IAuthApiClient, AuthApiClient>((sp, http) =>
    {
        var baseUrl = builder.Configuration["Api:BaseUrl"] ?? throw new InvalidOperationException("Missing Api:BaseUrl");
        http.BaseAddress = new Uri(baseUrl, UriKind.Absolute);
    }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AutomaticDecompression = System.Net.DecompressionMethods.GZip | System.Net.DecompressionMethods.Deflate
    });

builder.Services.AddHttpClient<IBackendApiClient, BackendApiClient>((sp, http) =>
    {
        var baseUrl = builder.Configuration["Api:BaseUrl"] ?? throw new InvalidOperationException("Missing Api:BaseUrl");
        http.BaseAddress = new Uri(baseUrl, UriKind.Absolute);
    })
    .AddHttpMessageHandler<ApiAuthHandler>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();