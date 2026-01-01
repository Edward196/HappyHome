namespace HappyHome.Application.Auth.Abstractions
{
    public interface ITokenService
    {
        Task<(string token, int expiresInSeconds, string[] roles)> CreateAccessTokenAsync(string userId);
    }
}
