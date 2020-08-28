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
        /// <typeparam name="TRavenUserStore">User store type.</typeparam>
        /// <typeparam name="TRavenRoleStore">Role store type.</typeparam>
        /// <typeparam name="TUser">Identity user type.</typeparam>
        /// <typeparam name="TRole">Identity role type.</typeparam>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores<TRavenUserStore, TRavenRoleStore, TUser, TRole>(
            this IdentityBuilder builder,
            Func<IServiceProvider, IdentityDocumentSessionProvider> documentSessionProvider)
            where TRavenUserStore : RavenUserStore<TUser, TRole>
            where TRavenRoleStore : RavenRoleStore<TRole, TUser>
            where TUser : RavenIdentityUser
            where TRole : RavenIdentityRole
        {
            AddStores<TRavenUserStore, TRavenRoleStore, TUser, TRole>(
                builder.Services,
                documentSessionProvider
            );
            return builder;
        }

        private static void AddStores<TRavenUserStore, TRavenRoleStore, TUser, TRole>(
            IServiceCollection services,
            Func<IServiceProvider, IdentityDocumentSessionProvider> documentSessionProvider)
            where TRavenUserStore : RavenUserStore<TUser, TRole>
            where TRavenRoleStore : RavenRoleStore<TRole, TUser>
            where TUser : RavenIdentityUser
            where TRole : RavenIdentityRole
        {
            if (documentSessionProvider == null)
            {
                throw new ArgumentNullException(nameof(documentSessionProvider));
            }

            services.TryAddTransient(provider => new IdentityErrorDescriber());
            services.TryAddTransient(documentSessionProvider);

            services.TryAddScoped<IUserStore<TUser>, TRavenUserStore>();
            services.TryAddScoped<IRoleStore<TRole>, TRavenRoleStore>();
        }
    }
}