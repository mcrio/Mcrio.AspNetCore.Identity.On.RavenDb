using System;
using System.Collections.Generic;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role
{
    /// <summary>
    /// class that represents the Identity Role.
    /// </summary>
    public class RavenIdentityRole : RavenIdentityRole<string, RavenIdentityClaim>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        /// <param name="id">Role id.</param>
        /// <param name="roleName">Role name.</param>
        public RavenIdentityRole(string id, string roleName)
            : base(id, roleName)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        public RavenIdentityRole()
        {
        }
    }

    /// <summary>
    /// Class representing the user identity role.
    /// </summary>
    /// <typeparam name="TKey">Type of the Id.</typeparam>
    /// <typeparam name="TRoleClaim">Type of role claim.</typeparam>
    public abstract class RavenIdentityRole<TKey, TRoleClaim> : IdentityRole<TKey>, IClaimsReader<TRoleClaim>,
        IClaimsWriter<TRoleClaim>
        where TKey : IEquatable<TKey>
        where TRoleClaim : RavenIdentityClaim
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        /// <param name="id">Role id.</param>
        /// <param name="roleName">Role Name.</param>
        public RavenIdentityRole(TKey id, string roleName)
            : base(roleName)
        {
            Id = id;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        protected RavenIdentityRole()
        {
        }

        /// <inheritdoc/>
        public sealed override TKey Id { get; set; } = default!;

        /// <inheritdoc/>
        public override string ConcurrencyStamp { get; set; } = string.Empty;

        /// <inheritdoc/>
        public IReadOnlyList<TRoleClaim> Claims { get; private set; } =
            new List<TRoleClaim>().AsReadOnly();

        /// <inheritdoc/>
        IReadOnlyList<TRoleClaim> IClaimsWriter<TRoleClaim>.Claims
        {
            set => Claims = value;
        }
    }
}