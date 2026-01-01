using HappyHome.Application.Auth.Abstractions;

namespace HappyHome.Application.Auth;

public class AuthService : IAuthService
{
    private readonly IIdentityService _identity;
    private readonly ITokenService _tokenService;
    private readonly ITokenCrypto _crypto;
    private readonly IRefreshTokenRepository _refreshRepo;
    private readonly JwtOptions _opt;

    public AuthService(
        IIdentityService identity,
        ITokenService tokenService,
        ITokenCrypto crypto,
        IRefreshTokenRepository refreshRepo,
        JwtOptions opt)
    {
        _identity = identity;
        _tokenService = tokenService;
        _crypto = crypto;
        _refreshRepo = refreshRepo;
        _opt = opt;
    }

    public async Task<TokenResponseDto> LoginAsync(LoginRequestDto dto)
    {
        var (ok, userId) = await _identity.ValidateUserAsync(dto.Username, dto.Password);
        if (!ok) throw new UnauthorizedAccessException("Login failed");

        var (jwt, expiresIn, roles) = await _tokenService.CreateAccessTokenAsync(userId);

        var refreshPlain = _crypto.GenerateSecureToken();
        var refreshHash = _crypto.HashToken(refreshPlain);

        await _refreshRepo.AddAsync(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = refreshHash,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_opt.RefreshTokenDays)
        });
        await _refreshRepo.SaveChangesAsync();

        return new TokenResponseDto
        {
            AccessToken = jwt,
            ExpiresIn = expiresIn,
            RefreshToken = refreshPlain
        };
    }

    public async Task<TokenResponseDto> RefreshAsync(RefreshRequestDto dto)
    {
        var hash = _crypto.HashToken(dto.RefreshToken);
        var rt = await _refreshRepo.FindByHashAsync(hash);
        if (rt == null || rt.RevokedAtUtc != null || rt.ExpiresAtUtc <= DateTime.UtcNow)
            throw new UnauthorizedAccessException("Refresh failed");

        // rotate
        rt.RevokedAtUtc = DateTime.UtcNow;

        var newPlain = _crypto.GenerateSecureToken();
        var newHash = _crypto.HashToken(newPlain);
        rt.ReplacedByTokenHash = newHash;

        await _refreshRepo.AddAsync(new RefreshToken
        {
            Id = Guid.NewGuid(),
            UserId = rt.UserId,
            TokenHash = newHash,
            CreatedAtUtc = DateTime.UtcNow,
            ExpiresAtUtc = DateTime.UtcNow.AddDays(_opt.RefreshTokenDays)
        });

        await _refreshRepo.SaveChangesAsync();

        var (jwt, expiresIn, roles) = await _tokenService.CreateAccessTokenAsync(rt.UserId);

        return new TokenResponseDto
        {
            AccessToken = jwt,
            ExpiresIn = expiresIn,
            RefreshToken = newPlain
        };
    }

    public async Task LogoutAsync(RefreshRequestDto dto)
    {
        var hash = _crypto.HashToken(dto.RefreshToken);
        var rt = await _refreshRepo.FindByHashAsync(hash);
        if (rt == null) return;

        if (rt.RevokedAtUtc == null)
            rt.RevokedAtUtc = DateTime.UtcNow;

        await _refreshRepo.SaveChangesAsync();
    }

    public async Task<MeResponseDto> MeAsync(string userId)
    {
        var info = await _identity.GetUserInfoAsync(userId);
        if (info == null) throw new UnauthorizedAccessException();

        return new MeResponseDto
        {
            UserId = userId,
            Username = info.Value.username,
            Roles = info.Value.roles.ToList()
        };
    }
}
