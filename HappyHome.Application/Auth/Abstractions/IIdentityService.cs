
namespace HappyHome.Application.Auth.Abstractions
{
    public interface IIdentityService
    {
        Task<(bool ok, string userId)> ValidateUserAsync(string username, string password);
        Task<(string username, string[] roles)?> GetUserInfoAsync(string userId);

        Task<(bool exists, string userId)> FindUserByEmailAsync(string email);
        Task<string?> GeneratePasswordResetTokenAsync(string userId);
        Task<bool> ResetPasswordAsync(string userId, string token, string newPassword);
    }
}