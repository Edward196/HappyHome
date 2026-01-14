using HappyHome.Application.Auth;

namespace HappyHome.Application.Auth.Abstractions
{
    public interface IAuthService
    {
        Task<TokenResponseDto> LoginAsync(LoginRequestDto dto);
        Task<TokenResponseDto> RefreshAsync(RefreshRequestDto dto);
        Task LogoutAsync(RefreshRequestDto dto);
        Task<MeResponseDto> MeAsync(string userId);

        Task ForgotPasswordAsync(ForgotPasswordRequestDto dto);
        Task ResetPasswordAsync(ResetPasswordRequestDto dto);
    }
}
