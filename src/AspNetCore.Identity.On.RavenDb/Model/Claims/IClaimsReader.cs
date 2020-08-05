using System.Collections.Generic;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims
{
    /// <summary>
    /// Provides an abstraction for reading identity claims.
    /// </summary>
    /// <typeparam name="TRoleClaim">Type of role claim.</typeparam>
    public interface IClaimsReader<out TRoleClaim>
        where TRoleClaim : RavenIdentityClaim
    {
        /// <summary>
        /// Claims the <see cref="IClaimsReader"/> implementer has.
        /// </summary>
        IReadOnlyList<TRoleClaim> Claims { get; }
    }
}