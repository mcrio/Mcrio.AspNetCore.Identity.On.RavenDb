using System.Collections.Generic;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims
{
    /// <summary>
    /// Provides an abstraction for writing identity claims.
    /// </summary>
    /// <typeparam name="TRoleClaim">Type of role claim.</typeparam>
    internal interface IClaimsWriter<in TRoleClaim>
        where TRoleClaim : RavenIdentityClaim
    {
        /// <summary>
        /// Sets the claims.
        /// </summary>
        IReadOnlyList<TRoleClaim> Claims { set; }
    }
}