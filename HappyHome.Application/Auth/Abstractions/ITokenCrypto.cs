
namespace HappyHome.Application.Auth.Abstractions
{
    public interface ITokenCrypto
    {
        string GenerateSecureToken();
        string HashToken(string token);
    }
}