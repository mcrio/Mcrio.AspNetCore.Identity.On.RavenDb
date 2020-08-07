using System;
using System.Diagnostics.CodeAnalysis;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;

namespace Mcrio.AspNetCore.Identity.RavenDb.Tests
{
    [SuppressMessage("ReSharper", "SA1600", Justification = "Suppress missing documentation warning for test.")]
    internal static class Initializer
    {
        public static RavenIdentityUser CreateTestUser(
            string? username = null,
            string email = "",
            string phoneNumber = "",
            bool lockoutEnabled = false,
            DateTimeOffset? lockoutEnd = default)
        {
            username ??= username ?? Guid.NewGuid().ToString();
            return new RavenIdentityUser(Guid.NewGuid().ToString(), username)
            {
                NormalizedUserName = username,
                Email = email,
                NormalizedEmail = email,
                PhoneNumber = phoneNumber,
                LockoutEnabled = lockoutEnabled,
                LockoutEnd = lockoutEnd,
                SecurityStamp = Guid.NewGuid().ToString(),
            };
        }

        public static RavenIdentityRole CreateTestRole(string? roleName = null)
        {
            roleName ??= Guid.NewGuid().ToString();
            var role = new RavenIdentityRole(
                Guid.NewGuid().ToString(),
                roleName)
            {
                NormalizedName = roleName,
            };
            return role;
        }
    }
}