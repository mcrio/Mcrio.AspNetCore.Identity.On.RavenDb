using System;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb
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
        /// <param name="collectionName">Collection name found.</param>
        /// <returns>Default collection name if known type otherwise Null.</returns>
        public static bool TryGetCollectionName(
            Type type,
            out string? collectionName)
        {
            if (typeof(RavenIdentityUser).IsAssignableFrom(type))
            {
                collectionName = "Users";
                return true;
            }

            if (typeof(RavenIdentityRole).IsAssignableFrom(type))
            {
                collectionName = "Roles";
                return true;
            }

            collectionName = null;
            return false;
        }
    }
}