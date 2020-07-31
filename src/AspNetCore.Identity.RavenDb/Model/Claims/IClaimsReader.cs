using System.Collections.Generic;

namespace Mcrio.AspNetCore.Identity.RavenDb.Model.Claims
{
    /// <summary>
    /// Provides an abstraction for reading identity claims.
    /// </summary>
    public interface IClaimsReader
    {
        /// <summary>
        /// Claims the <see cref="IClaimsReader"/> implementer has.
        /// </summary>
        IReadOnlyList<RavenIdentityClaim> Claims { get; }
    }
}