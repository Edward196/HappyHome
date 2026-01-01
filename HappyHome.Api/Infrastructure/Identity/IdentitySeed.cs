using Microsoft.AspNetCore.Identity;

namespace HappyHome.Api.Infrastructure.Identity
{
    public static class IdentitySeed
    {
        public static async Task SeedAdminAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();

            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

            // 1: Seed roles
            string[] roles = ["ADMIN", "MANAGER", "STAFF"];

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // 2: Seed admin user
            const string adminUsername = "admin";
            const string adminPassword = "Admin@123"; // 👉 đổi ở production

            var adminUser = await userManager.FindByNameAsync(adminUsername);
            if (adminUser == null)
            {
                adminUser = new IdentityUser
                {
                    UserName = adminUsername,
                    Email = "admin@happyhome.local",
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(adminUser, adminPassword);
                if (!result.Succeeded)
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    throw new Exception($"Failed to create admin user: {errors}");
                }
            }

            // 3: Ensure admin has ADMIN role
            if (!await userManager.IsInRoleAsync(adminUser, "ADMIN"))
            {
                await userManager.AddToRoleAsync(adminUser, "ADMIN");
            }
        }
    }
}
