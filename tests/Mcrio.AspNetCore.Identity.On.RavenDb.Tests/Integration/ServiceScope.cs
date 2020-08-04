using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Identity;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public class ServiceScope
    {
        internal ServiceScope(
            RoleManager<RavenIdentityRole> roleManager,
            UserManager<RavenIdentityUser> userManager,
            IDocumentStore documentStore,
            RavenUserStore userStore,
            RavenRoleStore roleStore,
            IAsyncDocumentSession documentSession)
        {
            RoleManager = roleManager;
            UserManager = userManager;
            UserStore = userStore;
            RoleStore = roleStore;
            DocumentSession = documentSession;
            DocumentStore = documentStore;
        }

        internal RoleManager<RavenIdentityRole> RoleManager { get; }

        internal UserManager<RavenIdentityUser> UserManager { get; }

        internal IDocumentStore DocumentStore { get; }

        internal RavenUserStore UserStore { get; }

        internal RavenRoleStore RoleStore { get; }

        internal IAsyncDocumentSession DocumentSession { get; }
    }
}