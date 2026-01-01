using Microsoft.AspNetCore.Identity;

namespace HappyHome.Api.Identity
{
    public static class IdentitySeed
    {
        public static async Task SeedAsync(IServiceProvider services)
        {
            using var scope = services.CreateScope();

            var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

            // 1️⃣ Seed roles
            string[] roles = ["ADMIN", "MANAGER", "STAFF"];

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // 2️⃣ Seed users
            await EnsureUserAsync(
                userManager,
                username: "admin",
                email: "admin@happyhome.local",
                password: "Admin@123",
                role: "ADMIN"
            );

            await EnsureUserAsync(
                userManager,
                username: "manager",
                email: "manager@happyhome.local",
                password: "Manager@123",
                role: "MANAGER"
            );

            await EnsureUserAsync(
                userManager,
                username: "staff",
                email: "staff@happyhome.local",
                password: "Staff@123",
                role: "STAFF"
            );
        }

        private static async Task EnsureUserAsync(
            UserManager<IdentityUser> userManager,
            string username,
            string email,
            string password,
            string role)
        {
            var user = await userManager.FindByNameAsync(username);
            if (user == null)
            {
                user = new IdentityUser
                {
                    UserName = username,
                    Email = email,
                    EmailConfirmed = true
                };

                var result = await userManager.CreateAsync(user, password);
                if (!result.Succeeded)
                {
                    var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                    throw new Exception($"Failed to create user '{username}': {errors}");
                }
            }

            if (!await userManager.IsInRoleAsync(user, role))
            {
                await userManager.AddToRoleAsync(user, role);
            }
        }
    }
}
