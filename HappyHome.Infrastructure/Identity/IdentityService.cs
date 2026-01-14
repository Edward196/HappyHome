using HappyHome.Application.Auth.Abstractions;
using Microsoft.AspNetCore.Identity;

namespace HappyHome.Infrastructure.Identity;

public class IdentityService : IIdentityService
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signIn;

    public IdentityService(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signIn)
    {
        _userManager = userManager;
        _signIn = signIn;
    }

    public async Task<(bool ok, string userId)> ValidateUserAsync(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null) return (false, "");

        var ok = (await _signIn.CheckPasswordSignInAsync(user, password, true)).Succeeded;
        return (ok, user.Id);
    }

    public async Task<(string username, string[] roles)?> GetUserInfoAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;

        var roles = await _userManager.GetRolesAsync(user);
        return (user.UserName ?? "", roles.ToArray());
    }

    public async Task<(bool exists, string userId)> FindUserByEmailAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        return user == null ? (false, "") : (true, user.Id);
    }

    public async Task<string?> GeneratePasswordResetTokenAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return null;
        return await _userManager.GeneratePasswordResetTokenAsync(user);
    }

    public async Task<bool> ResetPasswordAsync(string userId, string token, string newPassword)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null) return false;

        var result = await _userManager.ResetPasswordAsync(user, token, newPassword);
        return result.Succeeded;
    }
}
