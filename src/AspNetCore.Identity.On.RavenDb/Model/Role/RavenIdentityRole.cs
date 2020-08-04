using System;
using System.Collections.Generic;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role
{
    /// <summary>
    /// class that represents the Identity Role.
    /// </summary>
    public class RavenIdentityRole : RavenIdentityRole<string>
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
    public class RavenIdentityRole<TKey> : IdentityRole<TKey>, IClaimsReader, IClaimsWriter
        where TKey : IEquatable<TKey>
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
        public IReadOnlyList<RavenIdentityClaim> Claims { get; private set; } =
            new List<RavenIdentityClaim>().AsReadOnly();

        /// <inheritdoc/>
        IReadOnlyList<RavenIdentityClaim> IClaimsWriter.Claims
        {
            set => Claims = value;
        }
    }
}