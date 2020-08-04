using System;
using Raven.Client.Documents;
using Raven.TestDriver;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public class RavenDbFixture : RavenTestDriver, IDisposable
    {
        private readonly Lazy<IDocumentStore> _documentStore;

        public RavenDbFixture()
        {
            _documentStore = new Lazy<IDocumentStore>(CreateDocumentStore);
        }
        
        public IDocumentStore DocumentStore => _documentStore.Value;

        private IDocumentStore CreateDocumentStore()
        {
            return GetDocumentStore();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_documentStore.IsValueCreated)
                {
                    _documentStore.Value.Dispose();
                }
            }
        }

        public sealed override void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}