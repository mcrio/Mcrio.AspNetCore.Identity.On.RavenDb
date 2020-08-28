using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb
{
    /// <inheritdoc />
    internal class IdentityDocumentSessionWrapper : IIdentityDocumentSessionWrapper
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityDocumentSessionWrapper"/> class.
        /// </summary>
        /// <param name="session">RavenDB async document session.</param>
        internal IdentityDocumentSessionWrapper(IAsyncDocumentSession session)
        {
            Session = session;
        }

        /// <inheritdoc />
        public IAsyncDocumentSession Session { get; }
    }
}