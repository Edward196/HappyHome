namespace HappyHome.ManagementWeb.Services
{
    // Placeholder: bạn sẽ mở rộng cho Orders/Employees/Services…
    public interface IBackendApiClient
    {
        Task<string> PingAsync(CancellationToken ct = default);
    }
}
