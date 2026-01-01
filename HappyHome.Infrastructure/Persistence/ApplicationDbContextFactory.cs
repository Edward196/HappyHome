using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace HappyHome.Infrastructure.Persistence
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            // Read config from API project (startup) or current directory
            var basePath = Directory.GetCurrentDirectory();

            // Nếu bạn chạy lệnh ở root solution, basePath là root.
            // Ta trỏ vào HappyHome.Api để đọc appsettings (nơi có ConnectionStrings/Jwt).
            var apiPath = Path.Combine(basePath, "..", "HappyHome.Api");

            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.Exists(apiPath) ? apiPath : basePath)
                .AddJsonFile("appsettings.json", optional: false)
                .AddJsonFile("appsettings.Development.json", optional: true)
                .AddEnvironmentVariables()
                .Build();

            var cs = config.GetConnectionString("Default")
                     ?? throw new InvalidOperationException("Missing ConnectionStrings:Default");

            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
            optionsBuilder.UseMySql(cs, ServerVersion.AutoDetect(cs));

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
