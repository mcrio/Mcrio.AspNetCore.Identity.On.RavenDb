using System;
using System.Threading.Tasks;
using FluentAssertions;
using Mcrio.AspNetCore.Identity.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.RavenDb.Model.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Raven.Client.Documents;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using Raven.TestDriver;

namespace Mcrio.AspNetCore.Identity.RavenDb.Tests.Integration
{
    public abstract class IntegrationTestsBase<TUser, TKey, TRole> : RavenTestDriver
        where TUser : RavenIdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TRole : RavenIdentityRole<TKey>
    {
        private IDocumentStore? _documentStore;

        protected ServiceScope InitializeServices(
            bool requireUniqueEmail = false,
            bool protectPersonalData = false
        )
        {
            _documentStore ??= GetDocumentStore();

            var serviceCollection = new ServiceCollection();

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
            }).AddDefaultTokenProviders();

            serviceCollection.TryAddSingleton<IAsyncDocumentSession>(provider =>
                _documentStore.OpenAsyncSession()
            );

            serviceCollection.TryAddSingleton<IUserStore<RavenIdentityUser>>(
                provider => new RavenUserStore(
                    provider.GetRequiredService<IAsyncDocumentSession>(),
                    new IdentityErrorDescriber(),
                    provider.GetRequiredService<IOptions<IdentityOptions>>(),
                    new Mock<ILogger<RavenUserStore>>().Object
                )
            );
            serviceCollection.TryAddSingleton<IRoleStore<RavenIdentityRole>>(
                provider => new RavenRoleStore(
                    provider.GetRequiredService<IAsyncDocumentSession>(),
                    new IdentityErrorDescriber(),
                    new Mock<ILogger<RavenRoleStore>>().Object
                )
            );

            ServiceProvider serviceProvider = serviceCollection.BuildServiceProvider();

            return new ServiceScope(
                serviceProvider.GetRequiredService<RoleManager<RavenIdentityRole>>(),
                serviceProvider.GetRequiredService<UserManager<RavenIdentityUser>>(),
                _documentStore,
                (RavenUserStore)serviceProvider.GetRequiredService<IUserStore<RavenIdentityUser>>(),
                (RavenRoleStore)serviceProvider.GetRequiredService<IRoleStore<RavenIdentityRole>>(),
                serviceProvider.GetRequiredService<IAsyncDocumentSession>()
            );
        }

        protected async Task AssertCompareExchangeKeyExistsAsync(string cmpExchangeKey, string because = "")
        {
            var documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<string> result = await GetCompareExchangeAsync<string>(documentStore, cmpExchangeKey);
            result.Should().NotBeNull(
                because == null ? string.Empty : $"cmp exchange {cmpExchangeKey} should exist because {because}"
            );
        }

        protected async Task AssertCompareExchangeKeyExistsWithValueAsync<TValue>(
            string cmpExchangeKey,
            TValue value,
            string because = "")
        {
            var documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<TValue> result = await GetCompareExchangeAsync<TValue>(documentStore, cmpExchangeKey);
            result.Should().NotBeNull(
                because == null ? string.Empty : $"cmp exchange {cmpExchangeKey} should exist because {because}"
            );
            result.Value.Should().Be(value);
        }

        protected async Task AssertCompareExchangeKeyDoesNotExistAsync(string cmpExchangeKey, string because = "")
        {
            var documentStore = InitializeServices().DocumentStore;
            CompareExchangeValue<string> result = await GetCompareExchangeAsync<string>(documentStore, cmpExchangeKey);
            result.Should().BeNull(
                because == null ? string.Empty : $"cmp exchange {cmpExchangeKey} should not exist because {because}"
            );
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