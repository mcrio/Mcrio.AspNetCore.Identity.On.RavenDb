using System.Collections.Generic;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role
{
    /// <summary>
    /// Class that represents the Identity Role.
    /// </summary>
    public class RavenIdentityRole : RavenIdentityRole<RavenIdentityClaim>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        /// <param name="roleName">Role name.</param>
        public RavenIdentityRole(string roleName)
            : base(roleName)
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
    /// <typeparam name="TRoleClaim">Type of role claim.</typeparam>
    public abstract class RavenIdentityRole<TRoleClaim> : IdentityRole<string>, IClaimsReader<TRoleClaim>,
        IClaimsWriter<TRoleClaim>, IEntity
        where TRoleClaim : RavenIdentityClaim
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        /// <param name="roleName">Role Name.</param>
        protected RavenIdentityRole(string roleName)
            : base(roleName)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityRole"/> class.
        /// </summary>
        protected RavenIdentityRole()
        {
        }

        /// <summary>
        /// Gets the entity Id value.
        /// </summary>
        public sealed override string Id { get; set; } = default!;

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