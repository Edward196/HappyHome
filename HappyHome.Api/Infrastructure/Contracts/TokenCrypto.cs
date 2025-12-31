using System.Security.Cryptography;
using System.Text;
namespace HappyHome.Api.Infrastructure.Contracts;

public interface ITokenCrypto
{
    /// <summary>
    /// Generate a cryptographically secure random token (plain text)
    /// </summary>
    string GenerateSecureToken();

    /// <summary>
    /// Hash token for storage (never store plain token)
    /// </summary>
    string HashToken(string token);
}

public class TokenCrypto : ITokenCrypto
{
    // 64 bytes = very strong entropy
    private const int TOKEN_SIZE = 64;

    public string GenerateSecureToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(TOKEN_SIZE);
        return Convert.ToBase64String(bytes);
    }

    public string HashToken(string token)
    {
        using var sha = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = sha.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}
