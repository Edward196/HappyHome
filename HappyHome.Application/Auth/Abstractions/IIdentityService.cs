
namespace HappyHome.Application.Auth.Abstractions
{
    public interface IIdentityService
    {
        Task<(bool ok, string userId)> ValidateUserAsync(string username, string password);
        Task<(string username, string[] roles)?> GetUserInfoAsync(string userId);
    }
}