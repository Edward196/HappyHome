using HappyHome.Application.Auth;
using HappyHome.Application.Auth.Abstractions;
using HappyHome.Infrastructure.Identity;
using HappyHome.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace HappyHome.Infrastructure.Auth;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _db;
    public RefreshTokenRepository(ApplicationDbContext db) => _db = db;

    public async Task<RefreshToken?> FindByHashAsync(string tokenHash)
    {
        var e = await _db.RefreshTokens.SingleOrDefaultAsync(x => x.TokenHash == tokenHash);
        if (e == null) return null;

        return new RefreshToken
        {
            Id = e.Id,
            UserId = e.UserId,
            TokenHash = e.TokenHash,
            CreatedAtUtc = e.CreatedAtUtc,
            ExpiresAtUtc = e.ExpiresAtUtc,
            RevokedAtUtc = e.RevokedAtUtc,
            ReplacedByTokenHash = e.ReplacedByTokenHash
        };
    }

    public Task AddAsync(RefreshToken token)
    {
        _db.RefreshTokens.Add(new RefreshToken
        {
            Id = token.Id,
            UserId = token.UserId,
            TokenHash = token.TokenHash,
            CreatedAtUtc = token.CreatedAtUtc,
            ExpiresAtUtc = token.ExpiresAtUtc,
            RevokedAtUtc = token.RevokedAtUtc,
            ReplacedByTokenHash = token.ReplacedByTokenHash
        });
        return Task.CompletedTask;
    }

    public Task SaveChangesAsync() => _db.SaveChangesAsync();
}
