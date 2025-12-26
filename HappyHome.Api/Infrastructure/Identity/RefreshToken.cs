namespace HappyHome.API.Identity;

public class RefreshToken
{
    public long Id { get; set; }

    public string UserId { get; set; } = default!;
    public string TokenHash { get; set; } = default!;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }

    public DateTime? RevokedAtUtc { get; set; }

    // rotation
    public string? ReplacedByTokenHash { get; set; }

    public bool IsActive => RevokedAtUtc == null && DateTime.UtcNow < ExpiresAtUtc;
}
