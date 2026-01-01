namespace HappyHome.ManagementWeb.Services
{
    public interface IAuthApiClient
    {
        Task<TokenResponseDto> LoginAsync(LoginRequestDto dto, CancellationToken ct = default);
        Task<TokenResponseDto> RefreshAsync(RefreshRequestDto dto, CancellationToken ct = default);
        Task LogoutAsync(RefreshRequestDto dto, CancellationToken ct = default);
        Task<MeResponseDto> MeAsync(string accessToken, CancellationToken ct = default);
    }
}
