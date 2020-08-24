using System;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb
{
    /// <summary>
    /// Delegate which provides a <see cref="IAsyncDocumentSession"/> to be used as a RavenDB document session.
    /// </summary>
    /// <returns>RavenDB async document session.</returns>
    public delegate IAsyncDocumentSession IdentityDocumentSessionProvider();

    /// <summary>
    /// Extension methods to <see cref="IdentityBuilder"/> for adding RavenDB stores.
    /// </summary>
    public static class IdentityBuilderExtension
    {
        /// <summary>
        /// Adds the RavenDB implementation of ASP core identity stores.
        /// </summary>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="documentSessionProvider">RavenDB async document session provider.</param>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores(
            this IdentityBuilder builder,
            Func<IServiceProvider, IdentityDocumentSessionProvider> documentSessionProvider)
        {
            AddStores(builder.Services, builder.UserType, builder.RoleType, documentSessionProvider);
            return builder;
        }

        private static void AddStores(
            IServiceCollection services,
            Type userType,
            Type roleType,
            Func<IServiceProvider, IdentityDocumentSessionProvider> documentSessionProvider)
        {
            if (documentSessionProvider == null)
            {
                throw new ArgumentNullException(nameof(documentSessionProvider));
            }

            if (!typeof(RavenIdentityUser).IsAssignableFrom(userType))
            {
                throw new ArgumentException("User type must be of type RavenIdentityUser.");
            }

            if (!typeof(RavenIdentityRole).IsAssignableFrom(roleType))
            {
                throw new ArgumentException("Role type must be of type RavenIdentityRole.");
            }

            services.TryAddTransient(provider => new IdentityErrorDescriber());

            services.TryAddScoped<IdentityDocumentSessionProvider>(documentSessionProvider);

            Type userStoreType = typeof(RavenUserStore<,>).MakeGenericType(userType, roleType);
            Type roleStoreType = typeof(RavenRoleStore<,>).MakeGenericType(roleType, userType);

            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), userStoreType);
            services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), roleStoreType);
        }
    }
}