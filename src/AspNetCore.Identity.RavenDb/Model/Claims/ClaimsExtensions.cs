using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Mcrio.AspNetCore.Identity.RavenDb.Model.Claims
{
    /// <summary>
    /// Extensions for an object that has identity claims.
    /// </summary>
    public static class ClaimsExtensions
    {
        /// <summary>
        /// Checks whether the claim holder has the provided claim.
        /// </summary>
        /// <param name="holder">Claim holder.</param>
        /// <param name="claim">Claim to check for.</param>
        /// <returns>True if claim exists false otherwise.</returns>
        public static bool HasClaim(this IClaimsReader holder, Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader.Claims));
            }

            return holder.GetClaim(claim.Type, claim.Value) != null;
        }

        /// <summary>
        /// Adds a claim to the claim holders claims collection.
        /// </summary>
        /// <param name="holder">Claim holder.</param>
        /// <param name="claim">Claim to be added.</param>
        /// <returns>True if the claim did not exist before and was added. False if the claim already exists.</returns>
        public static bool AddClaim(this IClaimsReader holder, Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader.Claims));
            }

            if (holder.HasClaim(claim))
            {
                return false;
            }

            ((IClaimsWriter)holder).Claims = holder
                .Claims
                .Append(RavenIdentityClaim.FromClaim(claim))
                .ToList()
                .AsReadOnly();
            return true;
        }

        /// <summary>
        /// Removes the claim from the claim holders claims collection.
        /// </summary>
        /// <param name="holder">Claim holder.</param>
        /// <param name="claim">Claim to be added.</param>
        /// <returns>True if claim existed and was removed. False if the claim was not found in the collection.</returns>
        public static bool RemoveClaim(this IClaimsReader holder, Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader.Claims));
            }

            RavenIdentityClaim? existingClaim = holder.GetClaim(claim.Type, claim.Value);
            if (existingClaim == null)
            {
                return false;
            }

            ((IClaimsWriter)holder).Claims = holder
                .Claims
                .Where(item => item != existingClaim)
                .ToList()
                .AsReadOnly();
            return true;
        }

        /// <summary>
        /// Clears the existing claims list.
        /// </summary>
        /// <param name="holder">Claims holder.</param>
        public static void ClearClaims(this IClaimsReader holder)
        {
            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader.Claims));
            }

            ((IClaimsWriter)holder).Claims = new List<RavenIdentityClaim>().AsReadOnly();
        }

        /// <summary>
        /// Updates the value of the claim identified with the given type and value.
        /// </summary>
        /// <param name="holder">Claims holder.</param>
        /// <param name="oldClaim">Claim to be replaced.</param>
        /// <param name="newClaim">New claim to replace the old one.</param>
        /// <returns>True if there was a claim found and replaced, False otherwise</returns>
        public static bool ReplaceClaim(
            this IClaimsReader holder, Claim oldClaim, Claim newClaim)
        {
            if (oldClaim == null)
            {
                throw new ArgumentNullException(nameof(oldClaim));
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            RavenIdentityClaim? claim = holder.GetClaim(oldClaim.Type, oldClaim.Value);
            if (claim != null)
            {
                ((IClaimsWriter)(holder)).Claims = holder
                    .Claims
                    .Where(item => item != claim)
                    .Append(new RavenIdentityClaim(newClaim.Type, newClaim.Value))
                    .ToList()
                    .AsReadOnly();
                return true;
            }

            return false;
        }

        private static RavenIdentityClaim? GetClaim(this IClaimsReader holder, string claimType, string claimValue)
        {
            return holder.Claims
                .FirstOrDefault(e => e.Type == claimType && e.Value == claimValue);
        }
    }
}