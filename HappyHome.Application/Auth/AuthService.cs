using System.Text;
using HappyHome.Application.Auth.Abstractions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace HappyHome.Application.Auth;

public class AuthService : IAuthService
{
    private readonly IIdentityService _identity;
    private readonly ITokenService _tokenService;
    private readonly ITokenCrypto _crypto;
    private readonly IRefreshTokenRepository _refreshRepo;
    private readonly JwtOptions _opt;
    private readonly IEmailSender _email;

    public AuthService(
        IIdentityService identity,
        ITokenService tokenService,
        ITokenCrypto crypto,
        IRefreshTokenRepository refreshRepo,
        IEmailSender email,
        IOptions<JwtOptions> jwtOptions)
    {
        _identity = identity;
        _tokenService = tokenService;
        _crypto = crypto;
        _refreshRepo = refreshRepo;
        _email = email;
        _opt = jwtOptions.Value;
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

    public async Task ForgotPasswordAsync(ForgotPasswordRequestDto dto)
    {
        // Anti user-enumeration: luôn OK
        var email = (dto.Email ?? "").Trim();
        if (string.IsNullOrWhiteSpace(email)) return;

        var (exists, userId) = await _identity.FindUserByEmailAsync(email);
        if (!exists) return;

        var token = await _identity.GeneratePasswordResetTokenAsync(userId);
        if (string.IsNullOrWhiteSpace(token)) return;

        // Token Identity có ký tự đặc biệt -> base64url cho an toàn khi đưa lên URL
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        var tokenB64Url = WebEncoders.Base64UrlEncode(tokenBytes);

        if (string.IsNullOrWhiteSpace(_opt.ResetPasswordUrlTemplate))
            throw new InvalidOperationException("Missing Jwt:ResetPasswordUrlTemplate in configuration");

        var resetUrl = _opt.ResetPasswordUrlTemplate
            .Replace("{email}", Uri.EscapeDataString(email))
            .Replace("{token}", Uri.EscapeDataString(tokenB64Url));

        var subject = "Reset your HappyHome password";
        var body = $@"
                    <p>You requested a password reset.</p>
                    <p>Click this link to set a new password:</p>
                    <p><a href=""{resetUrl}"">Reset password</a></p>
                    <p>If you didn’t request this, ignore this email.</p>";

        await _email.SendAsync(email, subject, body);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequestDto dto)
    {
        var email = (dto.Email ?? "").Trim();
        var tokenB64 = (dto.Token ?? "").Trim();
        var newPwd = dto.NewPassword ?? "";

        if (string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(tokenB64) ||
            string.IsNullOrWhiteSpace(newPwd))
            throw new UnauthorizedAccessException("Invalid reset request");

        var (exists, userId) = await _identity.FindUserByEmailAsync(email);
        if (!exists) throw new UnauthorizedAccessException("Invalid reset request");

        string token;
        try
        {
            var tokenBytes = WebEncoders.Base64UrlDecode(tokenB64);
            token = Encoding.UTF8.GetString(tokenBytes);
        }
        catch
        {
            throw new UnauthorizedAccessException("Invalid reset token");
        }

        var ok = await _identity.ResetPasswordAsync(userId, token, newPwd);
        if (!ok) throw new UnauthorizedAccessException("Reset password failed");
    }
}
