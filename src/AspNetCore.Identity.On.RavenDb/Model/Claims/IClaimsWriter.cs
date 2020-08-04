using System.Collections.Generic;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims
{
    /// <summary>
    /// Provides an abstraction for writing identity claims.
    /// </summary>
    internal interface IClaimsWriter
    {
        /// <summary>
        /// Sets the claims.
        /// </summary>
        IReadOnlyList<RavenIdentityClaim> Claims { set; }
    }
}