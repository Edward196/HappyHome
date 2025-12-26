using HappyHome.ManagementWeb.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
// Session/Cookie setup
builder.Services.AddHttpContextAccessor();
builder.Services.AddSession();
builder.Services.AddAuthentication("Cookies").AddCookie("Cookies", opt =>
  {
      opt.LoginPath = "/Auth/Login";
      opt.AccessDeniedPath = "/Auth/Denied";
  });

// Token provider using Session
builder.Services.AddScoped<IApiTokenStore, SessionApiTokenStore>();

// Typed HttpClient to API

builder.Services.AddHttpClient<IAuthApiClient, AuthApiClient>(http =>
{
    http.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"]!);
});

builder.Services.AddTransient<ApiAuthHandler>();
builder.Services.AddHttpClient<IHappyHomeApiClient, HappyHomeApiClient>(http =>
{
    http.BaseAddress = new Uri(builder.Configuration["Api:BaseUrl"]!);
})
.AddHttpMessageHandler<ApiAuthHandler>();

builder.Services.AddAuthorization();

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

app.MapDefaultControllerRoute();
app.Run();