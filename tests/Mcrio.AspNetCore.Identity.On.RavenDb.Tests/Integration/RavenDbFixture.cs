using System;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Index;
using Raven.Client.Documents;
using Raven.TestDriver;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public class RavenDbFixture : RavenTestDriver, IDisposable
    {
        public RavenDbFixture()
        {
            DocumentStore = CreateDocumentStore();
            RavenDbIdentityIndexCreator.CreateIndexes<UsersByClaimIndex>(DocumentStore, DocumentStore.Database);
        }

        public IDocumentStore DocumentStore { get; }

        public sealed override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                DocumentStore.Dispose();
            }
        }

        private IDocumentStore CreateDocumentStore()
        {
            ConfigureServer(new TestServerOptions
            {
                Licensing =
                {
                    EulaAccepted = true,
                    LicensePath = RavenDbTestLicenseGetter.GetRavenDbDeveloperLicensePath(),
                },
            });
            return GetDocumentStore();
        }
    }
}