using System;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb
{
    /// <summary>
    /// Locates the document session.
    /// </summary>
    /// <param name="provider">Service provider.</param>
    /// <returns>Instance of an RavenDB async document session.</returns>
    public delegate IAsyncDocumentSession DocumentSessionServiceLocator(IServiceProvider provider);

    /// <summary>
    /// Extension methods to <see cref="IdentityBuilder"/> for adding RavenDB stores.
    /// </summary>
    public static class IdentityBuilderExtension
    {
        /// <summary>
        /// Adds the RavenDB implementation of ASP core identity stores.
        /// </summary>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="documentSessionServiceLocator">RavenDB async document session service locator..</param>
        /// <param name="uniqueValuesReservationOptionsConfig">Configure Unique value reservations options.</param>
        /// <typeparam name="TRavenUserStore">User store type.</typeparam>
        /// <typeparam name="TRavenRoleStore">Role store type.</typeparam>
        /// <typeparam name="TUser">Identity user type.</typeparam>
        /// <typeparam name="TRole">Identity role type.</typeparam>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores<TRavenUserStore, TRavenRoleStore, TUser, TRole>(
            this IdentityBuilder builder,
            DocumentSessionServiceLocator documentSessionServiceLocator,
            Action<UniqueValuesReservationOptions>? uniqueValuesReservationOptionsConfig = null)
            where TRavenUserStore : RavenUserStore<TUser, TRole, UniqueReservation>
            where TRavenRoleStore : RavenRoleStore<TRole, TUser, UniqueReservation>
            where TUser : RavenIdentityUser
            where TRole : RavenIdentityRole
        {
            return builder.AddRavenDbStores<TRavenUserStore, TRavenRoleStore, TUser, TRole, UniqueReservation>(
                documentSessionServiceLocator,
                uniqueValuesReservationOptionsConfig
            );
        }

        /// <summary>
        /// Adds the RavenDB implementation of ASP core identity stores.
        /// </summary>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <param name="documentSessionServiceLocator">RavenDB async document session service locator..</param>
        /// <param name="uniqueValuesReservationOptionsConfig">Configure Unique value reservations options.</param>
        /// <typeparam name="TRavenUserStore">User store type.</typeparam>
        /// <typeparam name="TRavenRoleStore">Role store type.</typeparam>
        /// <typeparam name="TUser">Identity user type.</typeparam>
        /// <typeparam name="TRole">Identity role type.</typeparam>
        /// <typeparam name="TUniqueReservationDoc">Unique values reservation document type.</typeparam>
        /// <returns>Returns the <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddRavenDbStores<
            TRavenUserStore,
            TRavenRoleStore,
            TUser,
            TRole,
            TUniqueReservationDoc>(
            this IdentityBuilder builder,
            DocumentSessionServiceLocator documentSessionServiceLocator,
            Action<UniqueValuesReservationOptions>? uniqueValuesReservationOptionsConfig = null)
            where TRavenUserStore : RavenUserStore<TUser, TRole, TUniqueReservationDoc>
            where TRavenRoleStore : RavenRoleStore<TRole, TUser, TUniqueReservationDoc>
            where TUser : RavenIdentityUser
            where TRole : RavenIdentityRole
            where TUniqueReservationDoc : UniqueReservation
        {
            AddStores<TRavenUserStore, TRavenRoleStore, TUser, TRole, TUniqueReservationDoc>(
                builder.Services,
                documentSessionServiceLocator,
                uniqueValuesReservationOptionsConfig
            );
            return builder;
        }

        private static void AddStores<TRavenUserStore, TRavenRoleStore, TUser, TRole, TUniqueReservationDoc>(
            IServiceCollection services,
            DocumentSessionServiceLocator documentSessionServiceLocator,
            Action<UniqueValuesReservationOptions>? uniqueValuesReservationOptionsConfig = null)
            where TRavenUserStore : RavenUserStore<TUser, TRole, TUniqueReservationDoc>
            where TRavenRoleStore : RavenRoleStore<TRole, TUser, TUniqueReservationDoc>
            where TUser : RavenIdentityUser
            where TRole : RavenIdentityRole
            where TUniqueReservationDoc : UniqueReservation
        {
            if (documentSessionServiceLocator == null)
            {
                throw new ArgumentNullException(nameof(documentSessionServiceLocator));
            }

            var uniqueValueRelatedOptions = new UniqueValuesReservationOptions();
            uniqueValuesReservationOptionsConfig?.Invoke(uniqueValueRelatedOptions);
            services.TryAddSingleton(uniqueValueRelatedOptions);

            services.TryAddTransient(provider => new IdentityErrorDescriber());

            services.TryAddScoped<IdentityDocumentSessionProvider>(
                provider => () => documentSessionServiceLocator(provider)
            );
            services.TryAddScoped<IUserStore<TUser>, TRavenUserStore>();
            services.TryAddScoped<IRoleStore<TRole>, TRavenRoleStore>();
        }
    }
}