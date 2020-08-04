using System;
using System.Security.Claims;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims
{
    /// <summary>
    /// Class representing the claims a user or role can have.
    /// </summary>
    public class RavenIdentityClaim
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityClaim"/> class.
        /// </summary>
        /// <param name="claimType">Type of the claim.</param>
        /// <param name="claimValue">Value of the claim.</param>
        public RavenIdentityClaim(string claimType, string claimValue)
        {
            Type = claimType ?? throw new ArgumentNullException(nameof(claimType));
            Value = claimValue ?? throw new ArgumentNullException(nameof(claimValue));
        }

        private RavenIdentityClaim()
        {
        }

        /// <summary>
        /// Gets the claim type for this claim.
        /// </summary>
        public string Type { get; private set; } = null!;

        /// <summary>
        /// Gets the claim value for this claim.
        /// </summary>
        public string Value { get; private set; } = null!;

        /// <summary>
        /// Initializes by copying ClaimType and ClaimValue from the other claim.
        /// </summary>
        /// <param name="claim">The claim to initialize from.</param>
        /// <returns>RavenDb identity role claim transformed from a Claim.</returns>
        public static RavenIdentityClaim FromClaim(Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            return new RavenIdentityClaim(claim.Type, claim.Value);
        }

        /// <summary>
        /// Constructs a new claim with the type and value.
        /// </summary>
        /// <returns>The <see cref="Claim"/> that was produced.</returns>
        public virtual Claim ToClaim()
        {
            return new Claim(Type, Value);
        }
    }
}