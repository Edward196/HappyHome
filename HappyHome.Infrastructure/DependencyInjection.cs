using HappyHome.Application.Auth.Abstractions;
using HappyHome.Application.Auth;
using HappyHome.Infrastructure.Identity;
using HappyHome.Infrastructure.Persistence;
using HappyHome.Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using HappyHome.Infrastructure.Auth;

namespace HappyHome.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.Configure<JwtOptions>(config.GetSection("Jwt"));

        var cs = config.GetConnectionString("Default")!;
        services.AddDbContext<ApplicationDbContext>(opt =>
            opt.UseMySql(cs, ServerVersion.AutoDetect(cs)));

        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        services.AddScoped<IIdentityService, IdentityService>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddSingleton<ITokenCrypto, TokenCrypto>();

        return services;
    }
}
