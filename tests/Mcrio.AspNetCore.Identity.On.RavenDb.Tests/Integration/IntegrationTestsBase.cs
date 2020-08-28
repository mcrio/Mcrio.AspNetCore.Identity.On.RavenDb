using System.Threading.Tasks;
using FluentAssertions;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Raven.Client.Documents;
using Raven.Client.Documents.Conventions;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using Raven.TestDriver;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public abstract class IntegrationTestsBase<TUser, TRole> : RavenTestDriver
        where TUser : RavenIdentityUser
        where TRole : RavenIdentityRole
    {
        private IDocumentStore? _documentStore;

        protected override void PreInitialize(IDocumentStore documentStore)
        {
            documentStore.Conventions.FindCollectionName = type =>
            {
                if (IdentityRavenDbConventions.TryGetCollectionName(
                    type,
                    out string? collectionName))
                {
                    return collectionName;
                }

                return DocumentConventions.DefaultGetCollectionName(type);
            };
        }

        protected ServiceScope InitializeServices(
            bool requireUniqueEmail = false,
            bool protectPersonalData = false
        )
        {
            _documentStore ??= GetDocumentStore();

            var serviceCollection = new ServiceCollection();

            serviceCollection.TryAddSingleton(provider =>
                _documentStore.OpenAsyncSession()
            );

            serviceCollection.AddHttpContextAccessor();
            serviceCollection.AddLogging();
            serviceCollection.AddDataProtection();
            serviceCollection.AddIdentity<TUser, TRole>(options =>
                {
                    options.Password.RequireDigit = false;
                    options.Password.RequireLowercase = false;
                    options.Password.RequireNonAlphanumeric = false;
                    options.Password.RequireUppercase = false;
                    options.User.RequireUniqueEmail = requireUniqueEmail;
                    options.Stores.ProtectPersonalData = protectPersonalData;
                })
                .AddRavenDbStores<RavenUserStore, RavenRoleStore, RavenIdentityUser, RavenIdentityRole>(
                    provider => provider.GetRequiredService<IAsyncDocumentSession>
                )
                .AddDefaultTokenProviders();

            ServiceProvider serviceProvider = serviceCollection.BuildServiceProvider();

            return new ServiceScope(
                serviceProvider.GetRequiredService<RoleManager<RavenIdentityRole>>(),
                serviceProvider.GetRequiredService<UserManager<RavenIdentityUser>>(),
                _documentStore,
                (RavenUserStore<RavenIdentityUser, RavenIdentityRole>)serviceProvider
                    .GetRequiredService<IUserStore<RavenIdentityUser>>(),
                (RavenRoleStore<RavenIdentityRole, RavenIdentityUser>)serviceProvider
                    .GetRequiredService<IRoleStore<RavenIdentityRole>>(),
                serviceProvider.GetRequiredService<IAsyncDocumentSession>()
            );
        }

        protected async Task AssertCompareExchangeKeyExistsAsync(string cmpExchangeKey, string because = "")
        {
            IDocumentStore documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<string> result = await GetCompareExchangeAsync<string>(documentStore, cmpExchangeKey);
            result.Should().NotBeNull($"cmp exchange {cmpExchangeKey} should exist because {because}");
        }

        protected async Task AssertCompareExchangeKeyExistsWithValueAsync<TValue>(
            string cmpExchangeKey,
            TValue value,
            string because = "")
        {
            IDocumentStore documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<TValue> result = await GetCompareExchangeAsync<TValue>(documentStore, cmpExchangeKey);
            result.Should().NotBeNull($"cmp exchange {cmpExchangeKey} should exist because {because}");
            result.Value.Should().Be(value);
        }

        protected async Task AssertCompareExchangeKeyDoesNotExistAsync(string cmpExchangeKey, string because = "")
        {
            IDocumentStore documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<string> result = await GetCompareExchangeAsync<string>(documentStore, cmpExchangeKey);
            result.Should().BeNull($"cmp exchange {cmpExchangeKey} should not exist because {because}");
        }

        private static Task<CompareExchangeValue<TValue>> GetCompareExchangeAsync<TValue>(
            IDocumentStore documentStore,
            string cmpExchangeKey)
        {
            return documentStore.Operations.SendAsync(
                new GetCompareExchangeValueOperation<TValue>(cmpExchangeKey)
            );
        }
    }
}