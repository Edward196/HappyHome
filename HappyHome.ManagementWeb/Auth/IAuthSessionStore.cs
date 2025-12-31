namespace HappyHome.ManagementWeb.Auth
{
    public interface IAuthSessionStore
    {
        AuthSession? Get();
        void Set(AuthSession session);
        void Clear();
    }
}