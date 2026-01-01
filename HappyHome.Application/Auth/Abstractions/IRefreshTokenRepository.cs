namespace HappyHome.Application.Auth.Abstractions;

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> FindByHashAsync(string tokenHash);
    Task AddAsync(RefreshToken token);
    Task SaveChangesAsync();
}
