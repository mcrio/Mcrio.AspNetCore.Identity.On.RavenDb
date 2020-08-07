using System;

namespace Mcrio.AspNetCore.Identity.On.RavenDb
{
    /// <summary>
    /// Method to produce predefined collection names for implemented entity types.
    /// </summary>
    public static class IdentityRavenDbConventions
    {
        /// <summary>
        /// If type is a implemented RavenDB identity type, returns a default collection name.
        /// </summary>
        /// <param name="type">Object type to get the collection for.</param>
        /// <typeparam name="TUser">Identity user type.</typeparam>
        /// <typeparam name="TRole">Identity role type.</typeparam>
        /// <returns>Default collection name if known type otherwise Null.</returns>
        public static string? GetIdentityCollectionName<TUser, TRole>(Type type)
        {
            if (typeof(TUser).IsAssignableFrom(type))
            {
                return "Users";
            }

            if (typeof(TRole).IsAssignableFrom(type))
            {
                return "Roles";
            }

            return null;
        }
    }
}