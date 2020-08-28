using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb
{
    /// <summary>
    /// Wrapper for the ravendb document session related to identity.
    /// </summary>
    public interface IIdentityDocumentSessionWrapper
    {
        /// <summary>
        /// Gets the RavenDB async document session.
        /// </summary>
        IAsyncDocumentSession Session { get; }
    }
}