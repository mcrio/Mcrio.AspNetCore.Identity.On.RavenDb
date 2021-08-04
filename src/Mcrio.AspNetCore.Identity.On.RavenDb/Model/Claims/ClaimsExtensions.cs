using System;
using System.Collections.Generic;
using System.Linq;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims
{
    /// <summary>
    /// Extensions for an object that has identity claims.
    /// </summary>
    public static class ClaimsExtensions
    {
        /// <summary>
        /// Checks whether the claim holder has the provided claim.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claim holder.</param>
        /// <param name="type">Claim type to check for.</param>
        /// <param name="value">Claim value to check for.</param>
        /// <returns>True if claim exists false otherwise.</returns>
        public static bool HasClaim<TClaim>(this IClaimsReader<TClaim> holder, string type, string value)
            where TClaim : RavenIdentityClaim
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader<TClaim>.Claims));
            }

            return holder.GetClaim(type, value) != null;
        }

        /// <summary>
        /// Checks whether the claim holder has the provided claim.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claim holder.</param>
        /// <param name="claim">Claim to check for.</param>
        /// <returns>True if claim exists false otherwise.</returns>
        public static bool HasClaim<TClaim>(this IClaimsReader<TClaim> holder, TClaim claim)
            where TClaim : RavenIdentityClaim
        {
            return holder.HasClaim(claim.Type, claim.Value);
        }

        /// <summary>
        /// Adds a claim to the claim holders claims collection.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claim holder.</param>
        /// <param name="claim">Claim to be added.</param>
        /// <returns>True if the claim did not exist before and was added. False if the claim already exists.</returns>
        public static bool AddClaim<TClaim>(this IClaimsReader<TClaim> holder, TClaim claim)
            where TClaim : RavenIdentityClaim
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader<TClaim>.Claims));
            }

            if (holder.HasClaim(claim))
            {
                return false;
            }

            ((IClaimsWriter<TClaim>)holder).Claims = holder
                .Claims
                .Append(claim)
                .ToList()
                .AsReadOnly();
            return true;
        }

        /// <summary>
        /// Removes the claim from the claim holders claims collection.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claim holder.</param>
        /// <param name="type">Type of claim to be removed.</param>
        /// <param name="value">Value of claim to be removed.</param>
        /// <returns>True if claim existed and was removed. False if the claim was not found in the collection.</returns>
        public static bool RemoveClaim<TClaim>(this IClaimsReader<TClaim> holder, string type, string value)
            where TClaim : RavenIdentityClaim
        {
            if (type == null)
            {
                throw new ArgumentNullException(nameof(type));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader<TClaim>.Claims));
            }

            TClaim? existingClaim = holder.GetClaim(type, value);
            if (existingClaim == null)
            {
                return false;
            }

            ((IClaimsWriter<TClaim>)holder).Claims = holder
                .Claims
                .Where(item => item != existingClaim)
                .ToList()
                .AsReadOnly();
            return true;
        }

        /// <summary>
        /// Clears the existing claims list.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claims holder.</param>
        public static void ClearClaims<TClaim>(this IClaimsReader<TClaim> holder)
            where TClaim : RavenIdentityClaim
        {
            if (holder.Claims == null)
            {
                throw new ArgumentNullException(nameof(IClaimsReader<TClaim>.Claims));
            }

            ((IClaimsWriter<TClaim>)holder).Claims = new List<TClaim>().AsReadOnly();
        }

        /// <summary>
        /// Updates the value of the claim identified with the given type and value.
        /// </summary>
        /// <typeparam name="TClaim">Type of claim.</typeparam>
        /// <param name="holder">Claims holder.</param>
        /// <param name="oldClaim">Claim to be replaced.</param>
        /// <param name="newClaim">New claim to replace the old one.</param>
        /// <returns>True if there was a claim found and replaced, False otherwise.</returns>
        public static bool ReplaceClaim<TClaim>(this IClaimsReader<TClaim> holder, TClaim oldClaim, TClaim newClaim)
            where TClaim : RavenIdentityClaim
        {
            if (oldClaim == null)
            {
                throw new ArgumentNullException(nameof(oldClaim));
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            TClaim? claim = holder.GetClaim(oldClaim.Type, oldClaim.Value);
            if (claim != null)
            {
                ((IClaimsWriter<TClaim>)(holder)).Claims = holder
                    .Claims
                    .Where(item => item != claim)
                    .Append(newClaim)
                    .ToList()
                    .AsReadOnly();
                return true;
            }

            return false;
        }

        private static TClaim? GetClaim<TClaim>(this IClaimsReader<TClaim> holder, string claimType, string claimValue)
            where TClaim : RavenIdentityClaim
        {
            return holder.Claims
                .FirstOrDefault(e => e.Type == claimType && e.Value == claimValue);
        }
    }
}