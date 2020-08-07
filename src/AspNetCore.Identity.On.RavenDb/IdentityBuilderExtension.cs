using System;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb
{
    /// <summary>
    /// Delegate which provides a <see cref="IAsyncDocumentSession"/> to be used as a RavenDB document session.
    /// </summary>
    /// <returns>RavenDB async document session.</returns>
    public delegate IAsyncDocumentSession DocumentSessionProvider();

    /// <summary>
    /// Extension methods to <see cref="IdentityBuilder"/> for adding RavenDB stores.
    /// </summary>
    public static class IdentityBuilderExtension
    {
        /// <summary>
        /// Adds the RavenDB implementation of ASP core identity stores.
        /// </summary>
        /// <param name="builder"><see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="documentSessionProvider">RavenDB async document session provider.</param>
        /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores(
            this IdentityBuilder builder,
            Func<IServiceProvider, DocumentSessionProvider> documentSessionProvider)
        {
            if (documentSessionProvider == null)
            {
                throw new ArgumentNullException(nameof(documentSessionProvider));
            }

            builder.Services.TryAddTransient(provider => new IdentityErrorDescriber());

            builder.Services.TryAddScoped<IUserStore<RavenIdentityUser>, RavenUserStore>();
            builder.Services.TryAddScoped<IRoleStore<RavenIdentityRole>, RavenRoleStore>();

            builder.Services.TryAddScoped<DocumentSessionProvider>(documentSessionProvider);

            return builder;
        }
    }
}