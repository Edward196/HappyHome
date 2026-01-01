using HappyHome.Application.Auth;
using HappyHome.Application.Auth.Abstractions;

namespace HappyHome.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        services.AddScoped<IAuthService, AuthService>();
        return services;
    }
}
