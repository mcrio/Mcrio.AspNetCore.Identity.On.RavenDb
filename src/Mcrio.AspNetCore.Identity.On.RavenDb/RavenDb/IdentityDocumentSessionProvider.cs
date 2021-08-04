using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb
{
    /// <summary>
    /// Provides the async document session.
    /// </summary>
    /// <returns>RavenDB async document session.</returns>
    public delegate IAsyncDocumentSession IdentityDocumentSessionProvider();
}