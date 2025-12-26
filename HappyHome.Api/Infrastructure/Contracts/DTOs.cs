namespace HappyHome.API.Contracts;

public record LoginRequest(string Username, string Password);

public record TokenResponse(
    string AccessToken,
    int ExpiresInSeconds,
    string RefreshToken,
    string TokenType,
    string UserName,
    string UserId,
    string[] Roles
);

public record RefreshRequest(string RefreshToken);