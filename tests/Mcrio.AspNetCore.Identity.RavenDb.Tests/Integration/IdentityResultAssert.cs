using Microsoft.AspNetCore.Identity;
using Xunit;

namespace Mcrio.AspNetCore.Identity.RavenDb.Tests.Integration
{
    /// <summary>
    /// Methods for identity results validation.
    /// </summary>
    internal static class IdentityResultAssert
    {
        /// <summary>
        /// Asserts that the result has succeeded.
        /// </summary>
        /// <param name="identityResult"></param>
        internal static void IsSuccess(IdentityResult identityResult)
        {
            Assert.NotNull(identityResult);
            Assert.True(identityResult.Succeeded);
        }

        /// <summary>
        /// Asserts that the result has failed.
        /// </summary>
        /// <param name="identityResult"></param>
        internal static void IsFailure(IdentityResult identityResult)
        {
            Assert.NotNull(identityResult);
            Assert.False(identityResult.Succeeded);
        }
    }
}