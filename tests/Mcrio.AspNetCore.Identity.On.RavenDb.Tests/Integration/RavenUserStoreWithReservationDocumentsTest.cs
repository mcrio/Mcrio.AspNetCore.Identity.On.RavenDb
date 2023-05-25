using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Raven.Client.Documents.Session;
using Xunit;
using static Mcrio.AspNetCore.Identity.RavenDb.Tests.Initializer;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public class RavenUserStoreWithReservationDocumentsTest : IntegrationTestsBase<RavenIdentityUser, RavenIdentityRole>
    {
        public static UniqueValuesReservationOptions UniquesUsingReservationDocuments() =>
            new UniqueValuesReservationOptions() { UseReservationDocumentsForUniqueValues = true, };

        [Fact]
        public async Task UserStoreMethodsThrowWhenDisposedTest()
        {
            var store = new RavenUserStore<RavenIdentityUser, RavenIdentityRole>(
                () => new Mock<IAsyncDocumentSession>().Object,
                new IdentityErrorDescriber(),
                Options.Create(new IdentityOptions()),
                new Mock<ILogger<RavenUserStore<RavenIdentityUser, RavenIdentityRole>>>().Object,
                UniquesUsingReservationDocuments()
            );

            store.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.AddClaimsAsync(CreateTestUser(), new List<Claim>()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                testCode: async () => await store.AddLoginAsync(
                    CreateTestUser(),
                    new UserLoginInfo("p", "k", "d")
                ));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.AddToRoleAsync(CreateTestUser(), "foo"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetClaimsAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetLoginsAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetRolesAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.IsInRoleAsync(CreateTestUser(), "foo"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.RemoveClaimsAsync(CreateTestUser(), new List<Claim>()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.RemoveLoginAsync(CreateTestUser(), "foo", "bar"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.RemoveFromRoleAsync(CreateTestUser(), "foo"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.RemoveClaimsAsync(CreateTestUser(), new Claim[0]));
            await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
                await store.ReplaceClaimAsync(
                    CreateTestUser(),
                    new Claim("foo", "bar"),
                    new Claim("bar", "baz")
                ));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.FindByLoginAsync("foo", "bar"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.FindByIdAsync("foo"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.FindByNameAsync("foo"));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.CreateAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.UpdateAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.DeleteAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.SetEmailConfirmedAsync(CreateTestUser(), true));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetEmailConfirmedAsync(CreateTestUser()));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.SetPhoneNumberConfirmedAsync(CreateTestUser(), true));
            await Assert.ThrowsAsync<ObjectDisposedException>(
                async () => await store.GetPhoneNumberConfirmedAsync(CreateTestUser()));
        }

        [Fact]
        public async Task UserStorePublicNullCheckTest()
        {
            var store = new RavenUserStore<RavenIdentityUser, RavenIdentityRole>(
                () => new Mock<IAsyncDocumentSession>().Object,
                new IdentityErrorDescriber(),
                Options.Create(new IdentityOptions()),
                new Mock<ILogger<RavenUserStore<RavenIdentityUser, RavenIdentityRole>>>().Object,
                UniquesUsingReservationDocuments()
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetUserIdAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetUserNameAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetUserNameAsync(null!, null)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.CreateAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.UpdateAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.DeleteAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.AddClaimsAsync(null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.ReplaceClaimAsync(null!, null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.RemoveClaimsAsync(null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetClaimsAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetLoginsAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetRolesAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.AddLoginAsync(null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.RemoveLoginAsync(null!, null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.AddToRoleAsync(null!, null!)
            );
            await
                Assert.ThrowsAsync<ArgumentNullException>(
                    "user",
                    async () => await store.RemoveFromRoleAsync(null!, null!)
                );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.IsInRoleAsync(null!, null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetPasswordHashAsync(null!)
            );
            await
                Assert.ThrowsAsync<ArgumentNullException>(
                    "user",
                    async () => await store.SetPasswordHashAsync(null!, null)
                );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetSecurityStampAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetSecurityStampAsync(null!, null)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "login",
                async () => await store.AddLoginAsync(
                    new RavenIdentityUser("fake"), null!
                )
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "claims",
                async () => await store.AddClaimsAsync(CreateTestUser(), null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "claims",
                async () => await store.RemoveClaimsAsync(CreateTestUser(), null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetEmailConfirmedAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetEmailConfirmedAsync(null!, true)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user", async () => await store.GetEmailAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user", async () => await store.SetEmailAsync(null!, null)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user", async () => await store.GetPhoneNumberAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetPhoneNumberAsync(null!, null)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetPhoneNumberConfirmedAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetPhoneNumberConfirmedAsync(null!, true)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetTwoFactorEnabledAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetTwoFactorEnabledAsync(null!, true)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetAccessFailedCountAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetLockoutEnabledAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetLockoutEnabledAsync(null!, false)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.GetLockoutEndDateAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.SetLockoutEndDateAsync(null!, default(DateTimeOffset))
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.ResetAccessFailedCountAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "user",
                async () => await store.IncrementAccessFailedCountAsync(null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.AddToRoleAsync(CreateTestUser(), null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.RemoveFromRoleAsync(CreateTestUser(), null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.IsInRoleAsync(CreateTestUser(), null!)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.AddToRoleAsync(CreateTestUser(), string.Empty)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.RemoveFromRoleAsync(CreateTestUser(), string.Empty)
            );
            await Assert.ThrowsAsync<ArgumentNullException>(
                "normalizedRoleName",
                async () => await store.IsInRoleAsync(CreateTestUser(), string.Empty)
            );
        }

        [Fact]
        public async Task ShouldCrateUserUsingUserManager()
        {
            var requireUniqueEmail = false;
            var scope = NewServiceScope(requireUniqueEmail);
            var manager = scope.UserManager;
            RavenIdentityUser user = CreateTestUser(email: "foo@bar.com");
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            WaitForIndexing(scope.DocumentStore);
            (await NewServiceScope().UserManager.FindByNameAsync(user.UserName)).Should().NotBeNull();
            (await NewServiceScope().UserManager.FindByIdAsync(user.Id)).Should().NotBeNull();

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                user.NormalizedUserName,
                user.Id,
                "user was created"
            );
            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                user.NormalizedEmail,
                "unique email is not required"
            );

            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldNotCrateUserIfUsernameTakenUsingStore()
        {
            var user1 = CreateTestUser("username");
            IdentityResultAssert.IsSuccess(
                await NewServiceScope().UserManager.CreateAsync(user1)
            );
            var user2 = CreateTestUser("username-2");
            IdentityResultAssert.IsSuccess(
                await NewServiceScope().UserManager.CreateAsync(user2)
            );
            var user3 = CreateTestUser("username-3");
            IdentityResultAssert.IsSuccess(
                await NewServiceScope().UserManager.CreateAsync(user3)
            );

            var scope = NewServiceScope();
            var store = scope.UserStore;
            var user = CreateTestUser("username-2");

            (await store.CreateAsync(user)).Succeeded.Should().BeFalse("because username is already taken");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username",
                user1.Id,
                "user exists"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username-2",
                user2.Id,
                "user exists"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username-3",
                user3.Id,
                "user exists"
            );

            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldNotCrateUserIfEmailTakenAndRequireUniqueEmailUsingStore()
        {
            const bool requireUniqueEmail = true;
            var manager = NewServiceScope(requireUniqueEmail).UserManager;
            var user1 = CreateTestUser("username", "foo@bar.com");
            IdentityResultAssert.IsSuccess(
                await manager.CreateAsync(
                    user1
                )
            );
            var user2 = CreateTestUser("username-2", "foo2@bar.com");
            IdentityResultAssert.IsSuccess(
                await manager.CreateAsync(
                    user2
                )
            );
            var user3 = CreateTestUser("username-3", "foo3@bar.com");
            IdentityResultAssert.IsSuccess(
                await manager.CreateAsync(
                    user3
                )
            );

            var scope = NewServiceScope(requireUniqueEmail);
            var store = scope.UserStore;
            var someUser = CreateTestUser("some-user", "foo2@bar.com");

            (await store.CreateAsync(someUser)).Succeeded.Should().BeFalse("email is already taken");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username",
                user1.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username-2",
                user2.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username-3",
                user3.Id,
                "user was created"
            );

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                user1.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo2@bar.com",
                user2.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo3@bar.com",
                user3.Id,
                "user was created"
            );

            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                "some-user",
                "user was not added due to unique email collision"
            );

            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldRemoveUserAndAddAgainUsingManager()
        {
            const bool requiredEmail = true;
            var scope = NewServiceScope(requiredEmail);
            var manager = scope.UserManager;
            var user = CreateTestUser("username", "foo@bar.com");
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            WaitForIndexing(scope.DocumentStore);

            (await NewServiceScope().UserManager.FindByIdAsync(user.Id)).Should().NotBeNull();
            (await NewServiceScope().UserManager.FindByNameAsync(user.UserName)).Should().NotBeNull();
            (await NewServiceScope().UserManager.FindByEmailAsync(user.Email)).Should().NotBeNull();

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username",
                user.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                user.Id,
                "user was created"
            );

            // delete user
            IdentityResultAssert.IsSuccess(await manager.DeleteAsync(user));
            WaitForIndexing(scope.DocumentStore);

            (await NewServiceScope().UserManager.FindByIdAsync(user.Id)).Should().BeNull();
            (await NewServiceScope().UserManager.FindByNameAsync(user.UserName)).Should().BeNull();
            (await NewServiceScope().UserManager.FindByEmailAsync(user.Email)).Should().BeNull();


            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                "username"
            );
            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Email,
                "foo@bar.com"
            );

            // reinsert user
            var scope2 = NewServiceScope(requiredEmail);
            var manager2 = scope2.UserManager;
            IdentityResultAssert.IsSuccess(await manager2.CreateAsync(user));
            WaitForIndexing(scope2.DocumentStore);

            (await NewServiceScope().UserManager.FindByIdAsync(user.Id)).Should().NotBeNull();
            (await NewServiceScope().UserManager.FindByNameAsync(user.UserName)).Should().NotBeNull();
            (await NewServiceScope().UserManager.FindByEmailAsync(user.Email)).Should().NotBeNull();

            WaitForUserToContinueTheTest(scope.DocumentStore);

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "username",
                user.Id,
                "user was created"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                user.Id,
                "user was created"
            );
        }

        [Fact]
        public async Task ShouldAddUserLoginUsingStore()
        {
            var user = CreateTestUser();
            user.Logins.Count.Should().Be(0);

            (await NewServiceScope().UserManager.CreateAsync(user))
                .Succeeded
                .Should().BeTrue();

            var scope = NewServiceScope();
            var store = scope.UserStore;

            var userRetrieved1 = await store.FindByIdAsync(user.Id);
            await store.AddLoginAsync(userRetrieved1, new UserLoginInfo("provider", "key", "name"));
            await store.AddLoginAsync(userRetrieved1, new UserLoginInfo("provider2", "key2", "name2"));
            await store.UpdateAsync(userRetrieved1);

            var manager2 = NewServiceScope().UserManager;
            var userRetrieved2 = await manager2.FindByIdAsync(user.Id);
            userRetrieved2.Should().NotBeNull();

            userRetrieved2.Logins.Count.Should().Be(2);
            userRetrieved2.Logins
                .Should()
                .Contain(info => info.LoginProvider == "provider" && info.ProviderKey == "key");
            userRetrieved2.Logins
                .Should()
                .Contain(info => info.LoginProvider == "provider2" && info.ProviderKey == "key2");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider/key",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider2/key2",
                user.Id
            );
        }

        [Fact]
        public async Task ShouldNotAddUserLoginIfOneAlreadyExistsWithSameProviderAndKeyUsingStore()
        {
            var scope = NewServiceScope();
            var manager = scope.UserManager;

            var user = CreateTestUser();
            user.Logins.Count.Should().Be(0);

            await manager.CreateAsync(user);
            (await manager.AddLoginAsync(user, new UserLoginInfo("provider", "key", "name")))
                .Succeeded
                .Should().BeTrue();

            var scope2 = NewServiceScope();
            var manager2 = scope2.UserManager;
            var store2 = scope2.UserStore;
            var anotherUser = CreateTestUser();
            anotherUser.Logins.Count.Should().Be(0);

            (await manager2.CreateAsync(anotherUser)).Succeeded.Should().BeTrue();
            await store2.AddLoginAsync(anotherUser, new UserLoginInfo("provider", "key", "name2"));
            (await store2.UpdateAsync(anotherUser)).Succeeded.Should().BeTrue();

            var anotherUserRetrieved = await NewServiceScope().UserManager.FindByIdAsync(anotherUser.Id);
            anotherUserRetrieved.Logins.Count.Should().Be(0);

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider/key",
                user.Id
            );
        }

        [Fact]
        public async Task ShouldNotAddDuplicateUserLoginIfAlreadyExistsWithSameProviderAndKeyUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.UserManager;

            var user = CreateTestUser();
            (await manager.CreateAsync(user)).Succeeded.Should().BeTrue();

            await manager.AddLoginAsync(user, new UserLoginInfo("provider", "key", "displayName"));
            await manager.AddLoginAsync(user, new UserLoginInfo("provider", "key", "displayNameOfDuplicate"));
            await manager.AddLoginAsync(user, new UserLoginInfo("provider2", "key2", "displayName"));

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider/key",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider2/key2",
                user.Id
            );

            var scope2 = NewServiceScope();
            var manager2 = scope2.UserManager;

            var retrievedUser = await manager2.FindByIdAsync(user.Id);
            retrievedUser.Logins.Count.Should().Be(2);
            retrievedUser
                .HasLogin(new RavenIdentityUserLogin("provider", "key", "displayName"))
                .Should()
                .BeTrue();
            retrievedUser
                .HasLogin(new RavenIdentityUserLogin("provider2", "key2", "displayName"))
                .Should()
                .BeTrue();

            (await manager2.AddLoginAsync(retrievedUser, new UserLoginInfo("provider3", "key3", "foo")))
                .Succeeded.Should().BeTrue();

            (await manager2.AddLoginAsync(retrievedUser, new UserLoginInfo("provider", "key", "baz")))
                .Succeeded.Should().BeFalse("already exists");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider/key",
                retrievedUser.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider2/key2",
                retrievedUser.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider3/key3",
                retrievedUser.Id
            );
        }

        [Fact]
        public async Task ShouldAddUserLoginAfterOneWithSameParametersWasRemovedUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.UserManager;

            var user = CreateTestUser();
            (await manager.CreateAsync(user)).Succeeded.Should().BeTrue();

            await manager.AddLoginAsync(user, new UserLoginInfo("provider", "key", "displayName"));
            await manager.AddLoginAsync(user, new UserLoginInfo("provider2", "key2", "displayName"));

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider/key",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Login,
                "provider2/key2",
                user.Id
            );

            var anotherUser = CreateTestUser();

            {
                var manager2 = NewServiceScope().UserManager;
                (await manager2.CreateAsync(anotherUser)).Succeeded.Should().BeTrue();
                (await manager2.AddLoginAsync(anotherUser, new UserLoginInfo("provider", "key", "displayName")))
                    .Succeeded.Should().BeFalse("there is already a login registered with the same parameters.");
            }

            (await manager.RemoveLoginAsync(user, "provider", "key")).Succeeded.Should().BeTrue();

            {
                var manager2 = NewServiceScope().UserManager;
                var anotherUserFromDb = await manager2.FindByIdAsync(anotherUser.Id);
                (await manager2.AddLoginAsync(anotherUserFromDb, new UserLoginInfo("provider", "key", "displayName")))
                    .Succeeded.Should().BeTrue("this login data no longer exists in the database.");
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Login,
                    "provider/key",
                    anotherUserFromDb.Id
                );
            }
        }

        [Fact]
        public async Task ShouldAddMultipleUserClaimsWithTheSameTypeButDifferentValuesUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims(
                claim1Type: "type",
                claim1Value: "value",
                claim2Type: "type",
                claim2Value: "value2"
            );
            user.Should().NotBeNull();

            var retrievedUser = await NewServiceScope().UserManager.FindByIdAsync(user.Id);

            retrievedUser.Claims.Count.Should().Be(2);
            retrievedUser.Claims.Should().ContainSingle(claim => claim.Type == "type" && claim.Value == "value");
            retrievedUser.Claims.Should().ContainSingle(claim => claim.Type == "type" && claim.Value == "value2");
        }

        [Fact]
        public async Task ShouldRemoveClaimsUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims(
                claim1Type: "type",
                claim1Value: "value",
                claim2Type: "type",
                claim2Value: "value2"
            );
            user.Should().NotBeNull();

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                await manager.RemoveClaimAsync(retrievedUser, new Claim("type", "value"));
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Claims.Count.Should().Be(1);
                retrievedUser.Claims.Should().ContainSingle(claim => claim.Type == "type" && claim.Value == "value2");
                await manager.AddClaimsAsync(retrievedUser, new[]
                {
                    new Claim("type99", "value99"),
                    new Claim("type100", "value100"),
                });
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Claims.Count.Should().Be(3);
                retrievedUser.Claims.Should().ContainSingle(claim => claim.Type == "type" && claim.Value == "value2");
                retrievedUser.Claims.Should()
                    .ContainSingle(claim => claim.Type == "type99" && claim.Value == "value99");
                retrievedUser.Claims.Should()
                    .ContainSingle(claim => claim.Type == "type100" && claim.Value == "value100");
                await manager.RemoveClaimsAsync(retrievedUser, new[]
                {
                    new Claim("type", "value2"),
                    new Claim("type100", "value100"),
                });
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Claims.Count.Should().Be(1);
                retrievedUser.Claims.Should()
                    .ContainSingle(claim => claim.Type == "type99" && claim.Value == "value99");
            }
        }

        [Fact]
        public async Task ShouldReplaceClaimUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims(
                claim1Type: "type",
                claim1Value: "value",
                claim2Type: "type",
                claim2Value: "value2"
            );
            user.Should().NotBeNull();

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                await manager.ReplaceClaimAsync(
                    retrievedUser,
                    new Claim("type", "value"),
                    new Claim("typeFoo", "valueFoo")
                );
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Claims.Count.Should().Be(2);
                retrievedUser.Claims.Should()
                    .ContainSingle(claim => claim.Type == "type" && claim.Value == "value2");
                retrievedUser.Claims.Should()
                    .ContainSingle(claim => claim.Type == "typeFoo" && claim.Value == "valueFoo");
            }
        }

        [Fact]
        public async Task ShouldGetUsersWithGivenClaimUsingManager()
        {
            var user1 = await SeedUserWithTwoRolesAndTwoClaims(
                userName: Guid.NewGuid().ToString(),
                claim1Type: "type",
                claim1Value: "value",
                claim2Type: "c2type",
                claim2Value: "c2value"
            );
            var user2 = await SeedUserWithTwoRolesAndTwoClaims(
                userName: Guid.NewGuid().ToString(),
                claim1Type: "type",
                claim1Value: "value",
                claim2Type: "c2type",
                claim2Value: "c2value"
            );
            await SeedUserWithTwoRolesAndTwoClaims(
                userName: Guid.NewGuid().ToString(),
                claim1Type: "type3993",
                claim1Value: "value",
                claim2Type: "c2type",
                claim2Value: "c2value"
            );
            await SeedUserWithTwoRolesAndTwoClaims(
                userName: Guid.NewGuid().ToString(),
                claim1Type: "foo1",
                claim1Value: "bar1",
                claim2Type: "foo2",
                claim2Value: "bar2"
            );
            await SeedUserWithTwoRolesAndTwoClaims(
                userName: Guid.NewGuid().ToString(),
                claim1Type: "foobar1",
                claim1Value: "foobar1V",
                claim2Type: "foobar2",
                claim2Value: "foobar2V"
            );
            IList<RavenIdentityUser> users = await NewServiceScope()
                .UserManager
                .GetUsersForClaimAsync(new Claim("type", "value"));

            users.Should().NotBeNull();
            users.Count.Should().Be(2);
            users.Select(item => item.Id).Should().Contain(new[] { user1.Id, user2.Id });
        }

        [Fact]
        public async Task ShouldUpdateUserTokenIfAlreadyExistsWithSameProviderAndNameUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                (await manager.SetAuthenticationTokenAsync(
                    retrievedUser,
                    "provider",
                    "tokenName",
                    "tokenValue"
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Tokens.Should().NotBeNull();
                retrievedUser.Tokens.Count.Should().Be(1);
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider" && token.Name == "tokenName"
                                                                              && token.Value == "tokenValue");
                (await manager.SetAuthenticationTokenAsync(
                    retrievedUser,
                    "provider",
                    "tokenName",
                    "tokenValue99"
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Tokens.Should().NotBeNull();
                retrievedUser.Tokens.Count.Should().Be(1);
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider" && token.Name == "tokenName"
                                                                              && token.Value == "tokenValue99");
            }
        }

        [Fact]
        public async Task ShouldDeleteUserToken()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                (await manager.SetAuthenticationTokenAsync(
                    retrievedUser,
                    "provider",
                    "tokenName",
                    "tokenValue"
                )).Succeeded.Should().BeTrue();
                (await manager.SetAuthenticationTokenAsync(
                    retrievedUser,
                    "provider2",
                    "tokenName2",
                    "tokenValue2"
                )).Succeeded.Should().BeTrue();
                (await manager.SetAuthenticationTokenAsync(
                    retrievedUser,
                    "provider3",
                    "tokenName3",
                    "tokenValue3"
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Tokens.Should().NotBeNull();
                retrievedUser.Tokens.Count.Should().Be(3);
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider" && token.Name == "tokenName"
                                                                              && token.Value == "tokenValue");
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider2" && token.Name == "tokenName2"
                                                                               && token.Value == "tokenValue2");
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider3" && token.Name == "tokenName3"
                                                                               && token.Value == "tokenValue3");
                (await manager.RemoveAuthenticationTokenAsync(
                    retrievedUser,
                    "provider",
                    "tokenName"
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Tokens.Should().NotBeNull();
                retrievedUser.Tokens.Count.Should().Be(2);
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider2" && token.Name == "tokenName2"
                                                                               && token.Value == "tokenValue2");
                retrievedUser
                    .Tokens
                    .Should()
                    .ContainSingle(token => token.LoginProvider == "provider3" && token.Name == "tokenName3"
                                                                               && token.Value == "tokenValue3");
            }
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnCreateWhenAutoSaveIsFalseUsingManager()
        {
            var scope = NewServiceScope();
            var store = scope.UserStore;
            store.AutoSaveChanges = false;
            var user = CreateTestUser();

            (await scope.UserManager.CreateAsync(user)).Succeeded.Should().BeTrue();

            (await NewServiceScope().UserManager.FindByIdAsync(user.Id))
                .Should()
                .BeNull("user data was not persisted as AutoSaveChanges is set to false");
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnUpdateWhenAutoSaveIsFalseUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();
            user.Claims.Count.Should().Be(2);

            {
                var scope = NewServiceScope();
                var manager = scope.UserManager;
                var store = scope.UserStore;
                store.AutoSaveChanges = false;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                (await scope.UserManager.AddClaimAsync(retrievedUser, new Claim("t", "v"))).Succeeded.Should().BeTrue();
                retrievedUser
                    .Claims
                    .Count
                    .Should()
                    .Be(3, "we added it to the user object but it should not be persisted to db");
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Should().NotBeNull();
                retrievedUser.Claims.Count
                    .Should()
                    .Be(2, "user data was not persisted as auto save is false");
            }
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnDeleteWhenAutoSaveIsFalseUsingManager()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();

            {
                var scope = NewServiceScope();
                var manager = scope.UserManager;
                var store = scope.UserStore;
                store.AutoSaveChanges = false;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                (await scope.UserManager.DeleteAsync(retrievedUser)).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var retrievedUser = await manager.FindByIdAsync(user.Id);
                retrievedUser.Should().NotBeNull("user store auto save changed on delete was disabled.");
            }
        }

        [Fact]
        public async Task ShouldUpdateMyEmailWithNullValueAsUniqueEmailIsNotRequired()
        {
            const bool requireUniqueEmail = false;

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;

                var user = CreateTestUser("some-user", "foo@bar.com");
                (await store.CreateAsync(user)).Succeeded.Should().BeTrue();

                await AssertReservationDocumentDoesNotExistAsync(
                    UniqueReservationType.Email,
                    "foo@bar.com"
                );
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    "some-user",
                    user.Id
                );
            }

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;

                var user = await store.FindByNameAsync("some-user");
                await store.SetEmailAsync(user, null);
                await store.SetNormalizedEmailAsync(user, null);
                await store.UpdateAsync(user);
            }
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldNotAddUserIfUserWithSameUsernameExistsWhenUsingStore()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();

            {
                var scope = NewServiceScope();
                var store = scope.UserStore;
                var result = await store.CreateAsync(CreateTestUser(user.UserName));
                result.Succeeded.Should().BeFalse();
                result.Errors
                    .Should()
                    .Contain(
                        error => error.Code == new IdentityErrorDescriber().DuplicateUserName(user.UserName).Code
                    );
            }

            {
                var retrievedUser = await NewServiceScope().UserManager.FindByIdAsync(user.Id);
                retrievedUser.Should().NotBeNull();
            }
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldAddUserAfterExistingUserWithSameUsernameChangesUsernameUsingStore()
        {
            const string username = "user12345";
            var user = await SeedUserWithTwoRolesAndTwoClaims(userName: username);
            user.Should().NotBeNull();

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                user.NormalizedUserName,
                user.Id
            );

            {
                var scope = NewServiceScope();
                var store = scope.UserStore;
                var result = await store.CreateAsync(CreateTestUser(username));
                result.Succeeded.Should().BeFalse();
                result.Errors
                    .Should()
                    .Contain(
                        error => error.Code == new IdentityErrorDescriber().DuplicateUserName(user.UserName).Code
                    );
            }

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                user.NormalizedUserName,
                user.Id
            );

            {
                var store = NewServiceScope().UserStore;
                var retrievedUser = await store.FindByIdAsync(user.Id);
                await store.SetUserNameAsync(retrievedUser, "test123");
                await store.SetNormalizedUserNameAsync(retrievedUser, "test123");
                await store.UpdateAsync(retrievedUser);

                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    "test123",
                    retrievedUser.Id
                );
            }

            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                user.NormalizedUserName
            );


            {
                var scope = NewServiceScope();
                var store = scope.UserStore;
                var newUser = CreateTestUser(username);
                var result = await store.CreateAsync(newUser);
                result.Succeeded.Should().BeTrue("existing user with same username previously renamed username");

                WaitForUserToContinueTheTest(scope.DocumentStore);

                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    username,
                    newUser.Id
                );
            }

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "test123",
                user.Id
            );
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldNotAddUserIfUserWithSameIdExistsWhenUsingStore()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            user.Should().NotBeNull();

            {
                var scope = NewServiceScope();
                var store = scope.UserStore;
                var user2 = CreateTestUser();
                user2.Id = user.Id;
                user2.Id.Should().BeSameAs(user.Id);
                var result = await store.CreateAsync(user2);
                result.Succeeded.Should().BeFalse();
                result.Errors
                    .Should()
                    .Contain(error => error.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
            }
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldCreateUserIfEmailUniqueRequiredAndAfterExistingUserWithSameEmailChangesEmailUsingStore()
        {
            const bool requireUniqueEmail = true;

            var someUser = CreateTestUser("some-user", "foo@bar.com");

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;


                (await store.CreateAsync(someUser)).Succeeded.Should().BeTrue();
            }

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;

                var user2 = CreateTestUser("some-user-2", "foo@bar.com");
                (await store.CreateAsync(user2)).Succeeded.Should().BeFalse("user with same email exists.");
            }

            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                "some-user-2"
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user",
                someUser.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                someUser.Id
            );

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;

                var user = await store.FindByNameAsync("some-user");
                await store.SetEmailAsync(user, "baz@baz.com");
                await store.SetNormalizedEmailAsync(user, "baz@baz.com");
                await store.UpdateAsync(user);

                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    "some-user",
                    user.Id
                );
                await AssertReservationDocumentDoesNotExistAsync(
                    UniqueReservationType.Username,
                    "some-user-2"
                );

                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Email,
                    "baz@baz.com",
                    user.Id
                );
                await AssertReservationDocumentDoesNotExistAsync(
                    UniqueReservationType.Email,
                    "foo@bar.com"
                );
            }

            {
                var scope = NewServiceScope(requireUniqueEmail);
                var store = scope.UserStore;

                var user2 = CreateTestUser("some-user-2", "foo@bar.com");
                (await store.CreateAsync(user2)).Succeeded.Should().BeTrue();

                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    "some-user",
                    someUser.Id
                );
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Email,
                    "baz@baz.com",
                    someUser.Id
                );
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Username,
                    "some-user-2",
                    user2.Id
                );
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Email,
                    "foo@bar.com",
                    user2.Id
                );
            }
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldCreateUserWithExistingEmailIfEmailUniquenessNotRequiredWhenUsingStoreDirectly()
        {
            var requireUniqueEmail = false;
            var scope = NewServiceScope(requireUniqueEmail);
            var store = scope.UserStore;

            var user = CreateTestUser("some-user", "foo@bar.com");
            (await store.CreateAsync(user)).Succeeded.Should().BeTrue();

            var user2 = CreateTestUser("some-user-2", "foo@bar.com");
            (await store.CreateAsync(user2)).Succeeded.Should().BeTrue("unique email is not required");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user-2",
                user2.Id
            );
            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Email,
                "foo@bar.com"
            );
        }

        [Fact]
        public async Task ShouldNotCreateUserWithExistingEmailIfEmailUniqueRequiredWhenUsingManager()
        {
            const bool requireUniqueEmail = true;
            var scope = NewServiceScope(requireUniqueEmail);
            var manager = scope.UserManager;

            var user = CreateTestUser("some-user", "foo@bar.com");
            (await manager.CreateAsync(user)).Succeeded.Should().BeTrue();

            WaitForIndexing(scope.DocumentStore);

            var user2 = CreateTestUser("some-user-2", "foo@bar.com");
            (await manager.CreateAsync(user2)).Succeeded.Should().BeFalse("user with same email exists.");

            WaitForIndexing(scope.DocumentStore);

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                user.Id
            );
            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Username,
                "some-user-2"
            );

            var user3 = CreateTestUser("some-user-3", "foo3@bar.com");
            (await manager.CreateAsync(user3)).Succeeded.Should().BeTrue("has different email");

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo@bar.com",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user-3",
                user3.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Email,
                "foo3@bar.com",
                user3.Id
            );
        }

        [Fact]
        public async Task ShouldCreateUserWithExistingEmailIfEmailUniquenessNotRequiredWhenUsingManager()
        {
            var requireUniqueEmail = false;
            var scope = NewServiceScope(requireUniqueEmail);
            var manager = scope.UserManager;

            var user = CreateTestUser("some-user", "foo@bar.com");
            (await manager.CreateAsync(user)).Succeeded.Should().BeTrue();

            WaitForIndexing(scope.DocumentStore);

            var user2 = CreateTestUser("some-user-2", "foo@bar.com");
            (await manager.CreateAsync(user2)).Succeeded.Should().BeTrue("unique email is not required");

            WaitForIndexing(scope.DocumentStore);

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user",
                user.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Username,
                "some-user-2",
                user2.Id
            );
            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Email,
                "foo@bar.com"
            );
        }

        [Fact]
        public async Task TwoUsersSamePasswordDifferentHash()
        {
            var manager = NewServiceScope().UserManager;
            var userA = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userA, "password"));

            var userB = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userB, "password"));

            Assert.NotEqual(userA.PasswordHash, userB.PasswordHash);
        }

        [Fact]
        public async Task FindByEmailThrowsWithTwoUsersWithSameEmail()
        {
            var scope = NewServiceScope();
            var manager = scope.UserManager;
            var userA = CreateTestUser();
            userA.Email = "dupe@dupe.com";
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userA, "password"));

            WaitForIndexing(scope.DocumentStore);

            var userB = CreateTestUser();
            userB.Email = "dupe@dupe.com";
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(userB, "password"));

            WaitForIndexing(scope.DocumentStore);

            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await manager.FindByEmailAsync("dupe@dupe.com")
            );
        }

        [Fact]
        public async Task AddUserToUnknownRoleFails()
        {
            var manager = NewServiceScope().UserManager;
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await manager.AddToRoleAsync(user, "bogus")
            );
        }

        [Fact]
        public async Task ConcurrentUpdatesWillFail()
        {
            var user = CreateTestUser();
            await NewServiceScope().UserManager.CreateAsync(user);

            {
                var manager1 = NewServiceScope().UserManager;
                var userFromSession1 = await manager1.FindByIdAsync(user.Id);

                var manager2 = NewServiceScope().UserManager;
                var userFromSession2 = await manager2.FindByIdAsync(user.Id);

                (await manager2.AddClaimAsync(userFromSession2, new Claim("cl", "va")))
                    .Succeeded.Should().BeTrue();

                var addClaimResult = await manager1.AddClaimAsync(userFromSession1, new Claim("foo", "bar"));
                addClaimResult.Succeeded.Should().BeFalse("user already modified in another session");
                addClaimResult.Errors
                    .Should()
                    .Contain(error => error.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
            }
        }

        [Fact]
        public async Task DeleteAModifiedUserWithUniqueValueUpdateWillFail()
        {
            var user = CreateTestUser();
            await NewServiceScope().UserManager.CreateAsync(user);

            {
                var manager1 = NewServiceScope().UserManager;
                var userFromSession1 = await manager1.FindByIdAsync(user.Id);

                var manager2 = NewServiceScope().UserManager;
                var userFromSession2 = await manager2.FindByIdAsync(user.Id);

                (await manager2.SetUserNameAsync(userFromSession2, Guid.NewGuid().ToString()))
                    .Succeeded.Should().BeTrue();

                var addClaimResult = await manager1.DeleteAsync(userFromSession1);
                addClaimResult.Succeeded.Should().BeFalse("user modified in another session");
                addClaimResult.Errors
                    .Should()
                    .Contain(error => error.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
            }
        }

        [Fact]
        public async Task ShouldRetrieveUserRolesInOneRoundtripUsingStore()
        {
            var userId = Guid.NewGuid().ToString();
            await SeedUserWithTwoRolesAndTwoClaims(userId);

            var scope = NewServiceScope();
            var manager = scope.UserManager;

            RavenIdentityUser user = await manager.FindByIdAsync(userId);

            int requestCountStart = scope.DocumentSession.Advanced.NumberOfRequests;

            var roles = await manager.GetRolesAsync(user);
            roles.Should().NotBeNull();
            roles.Count.Should().Be(2);

            int requestCountEnd = scope.DocumentSession.Advanced.NumberOfRequests;
            (requestCountEnd - requestCountStart).Should().Be(1);
        }

        [Fact]
        public async Task ShouldGetUsersInRole()
        {
            var testRole = CreateTestRole("testRole");
            await NewServiceScope().RoleManager.CreateAsync(testRole);

            WaitForIndexing(NewServiceScope().DocumentStore);

            var user1 = CreateTestUser();
            var user2 = CreateTestUser();
            var user3 = CreateTestUser();

            (await NewServiceScope().UserManager.CreateAsync(user1)).Succeeded.Should().BeTrue();
            (await NewServiceScope().UserManager.CreateAsync(user2)).Succeeded.Should().BeTrue();
            (await NewServiceScope().UserManager.CreateAsync(user3)).Succeeded.Should().BeTrue();

            {
                var manager = NewServiceScope().UserManager;
                var user1FromDb = await manager.FindByIdAsync(user1.Id);
                var user3FromDb = await manager.FindByIdAsync(user3.Id);
                (await manager.AddToRoleAsync(user1FromDb, testRole.Name)).Succeeded.Should().BeTrue();
                (await manager.AddToRoleAsync(user3FromDb, testRole.Name)).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var usersInRole = await manager.GetUsersInRoleAsync(testRole.Name);
                usersInRole.Count().Should().Be(2);
                usersInRole.Select(item => item.Id).ToList().Should().Contain(
                    new[] { user1.Id, user3.Id }
                );
            }
        }

        [Fact]
        public async Task ShouldAddUserToRole()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            var testRole = CreateTestRole("testRole1");
            await NewServiceScope().RoleManager.CreateAsync(testRole);

            WaitForIndexing(NewServiceScope().DocumentStore);

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                (await manager.AddToRoleAsync(userFromDb, testRole.Name)).Succeeded.Should().BeTrue();
            }

            var testRole2 = CreateTestRole("testRole2");
            var testRole3 = CreateTestRole("testRole3");
            await NewServiceScope().RoleManager.CreateAsync(testRole2);
            await NewServiceScope().RoleManager.CreateAsync(testRole3);

            WaitForIndexing(NewServiceScope().DocumentStore);

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                userFromDb.Roles.Count().Should().Be(3);
                userFromDb.Roles.Should().Contain(user.Roles.Append(testRole.Id));
                (await manager.AddToRolesAsync(
                    userFromDb,
                    new[] { testRole2.Name, testRole3.Name }
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                userFromDb.Roles.Count().Should().Be(5);
                userFromDb.Roles.Should().Contain(
                    user.Roles.Append(testRole.Id).Append(testRole2.Id).Append(testRole3.Id)
                );
            }
        }

        [Fact]
        public async Task ShouldRemoveUserFromRole()
        {
            var user = await SeedUserWithTwoRolesAndTwoClaims();
            var testRole = CreateTestRole("testRole1");
            var testRole2 = CreateTestRole("testRole2");
            var testRole3 = CreateTestRole("testRole3");
            await NewServiceScope().RoleManager.CreateAsync(testRole);
            await NewServiceScope().RoleManager.CreateAsync(testRole2);
            await NewServiceScope().RoleManager.CreateAsync(testRole3);

            WaitForIndexing(NewServiceScope().DocumentStore);

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                (await manager.AddToRolesAsync(userFromDb, new[]
                {
                    testRole.Name,
                    testRole2.Name,
                    testRole3.Name,
                })).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                userFromDb.Roles.Count().Should().Be(5);
                (await manager.RemoveFromRoleAsync(userFromDb, testRole.Name)).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                userFromDb.Roles.Count().Should().Be(4);
                userFromDb.Roles.Should().Contain(
                    user.Roles.Append(testRole2.Id).Append(testRole3.Id)
                );
                (await manager.RemoveFromRolesAsync(
                    userFromDb,
                    new[] { testRole2.Name, testRole3.Name }
                )).Succeeded.Should().BeTrue();
            }

            {
                var manager = NewServiceScope().UserManager;
                var userFromDb = await manager.FindByIdAsync(user.Id);
                userFromDb.Roles.Count().Should().Be(2);
                userFromDb.Roles.Should().Contain(user.Roles);
            }
        }

        private ServiceScope NewServiceScope(bool requireUniqueEmail = false, bool protectPersonalData = false)
            => InitializeServices(
                options => options.UseReservationDocumentsForUniqueValues = true,
                requireUniqueEmail,
                protectPersonalData
            );

        private async Task<RavenIdentityUser> SeedUserWithTwoRolesAndTwoClaims(
            string? userId = null,
            string userName = "user1",
            string role1Name = "role1",
            string role2Name = "role2",
            string claim1Type = "type",
            string claim1Value = "value",
            string claim2Type = "type2",
            string claim2Value = "value2")
        {
            var scope = NewServiceScope();

            var role1 = CreateTestRole(role1Name);
            var role2 = CreateTestRole(role2Name);

            await scope.RoleManager.CreateAsync(role1);
            await scope.RoleManager.CreateAsync(role2);

            var user = CreateTestUser(userName);

            if (userId != null)
            {
                user.Id = userId;
            }

            user.AddRole(role1.Id);
            user.AddRole(role2.Id);

            user.AddClaim(new RavenIdentityClaim(claim1Type, claim1Value));
            user.AddClaim(new RavenIdentityClaim(claim2Type, claim2Value));

            await scope.UserManager.CreateAsync(user);
            return user;
        }
    }
}