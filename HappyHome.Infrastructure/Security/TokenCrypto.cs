using System.Security.Cryptography;
using System.Text;
using HappyHome.Application.Auth.Abstractions;
namespace HappyHome.Infrastructure.Security;

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
