using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using FluentAssertions;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility;
using Microsoft.AspNetCore.Identity;
using Xunit;
using static Mcrio.AspNetCore.Identity.RavenDb.Tests.Initializer;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration
{
    public class RavenRoleStoreWithReservationDocumentsTest : IntegrationTestsBase<RavenIdentityUser, RavenIdentityRole>
    {
        [Fact]
        public async Task ShouldCreateRoleUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            Assert.NotNull(manager);

            var role = CreateTestRole();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(role));
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                role.NormalizedName,
                role.Id
            );

            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldCreateRoleWithIsAsNullUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            Assert.NotNull(manager);

            var role = CreateTestRole();
            role.Id = null!;
            role.Id.Should().BeNull();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(role));
            role.Id.Should().NotBeNull("RavenDb automatically assigned an ID.");
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                role.NormalizedName,
                role.Id
            );
            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldUpdateRoleNameToNonExistingOneUsingManager()
        {
            var scope = NewServiceScope();
            var roleId = Guid.NewGuid().ToString();
            {
                var manager = scope.RoleManager;
                var role = CreateTestRole("initialName");
                role.Id = roleId;

                (await manager.CreateAsync(role)).Succeeded.Should().BeTrue();
                WaitForIndexing(scope.DocumentStore);
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Role,
                    role.NormalizedName,
                    role.Id
                );
            }

            {
                var manager2 = NewServiceScope().RoleManager;
                var role = await manager2.FindByNameAsync("initialName");
                role.Should().NotBeNull();
                (await manager2.SetRoleNameAsync(role, "updatedName")).Succeeded.Should().BeTrue();
                (await manager2.UpdateAsync(role)).Succeeded.Should().BeTrue();
                WaitForIndexing(scope.DocumentStore);
                await AssertReservationDocumentExistsWithValueAsync(
                    UniqueReservationType.Role,
                    "updatedName",
                    role.Id
                );
                await AssertReservationDocumentDoesNotExistAsync(
                    UniqueReservationType.Role,
                    "initialName"
                );
            }

            {
                var manager3 = NewServiceScope().RoleManager;
                (await manager3.FindByNameAsync("initialName")).Should().BeNull();
                (await manager3.FindByNameAsync("updatedName")).Should().NotBeNull();
                (await manager3.FindByNameAsync("updatedName")).Id.Should().Be(roleId);
            }

            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        [Fact]
        public async Task ShouldNotUpdateRoleNameIfAlreadyExistsWhenUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            var role = CreateTestRole("role");
            var role2 = CreateTestRole("role2");

            (await manager.CreateAsync(role)).Succeeded.Should().BeTrue();
            (await manager.CreateAsync(role2)).Succeeded.Should().BeTrue();
            WaitForIndexing(scope.DocumentStore);

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                "role",
                role.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                "role2",
                role2.Id
            );

            (await manager.FindByNameAsync("role")).Should().NotBeNull();
            (await manager.FindByNameAsync("role2")).Should().NotBeNull();

            (await manager.SetRoleNameAsync(role, "role2")).Succeeded.Should().BeTrue();
            (await manager.UpdateAsync(role)).Succeeded.Should().BeFalse();

            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                "role",
                role.Id
            );
            await AssertReservationDocumentExistsWithValueAsync(
                UniqueReservationType.Role,
                "role2",
                role2.Id
            );
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldNotCreateRoleIfAnotherWithSameNameExistsWhenUsingStoreDirectly()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            var role = CreateTestRole("role");
            (await manager.CreateAsync(role)).Succeeded.Should().BeTrue();

            // save this role using the store directly, to bypass manager internal validation
            var role2 = CreateTestRole(role.Name);
            role2.NormalizedName = role.NormalizedName;
            (await NewServiceScope().RoleStore.CreateAsync(role2)).Succeeded.Should().BeFalse();
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldNotCreateRoleIfAnotherWithSameIdExistsWhenUsingStoreDirectly()
        {
            var role1Id = Guid.NewGuid().ToString();
            var role2Id = role1Id;
            var role3Id = Guid.NewGuid().ToString();

            var role1 = CreateTestRole("role1");
            role1.NormalizedName = "role1";
            role1.Id = role1Id;

            var role2 = CreateTestRole("role2");
            role2.NormalizedName = "role2";
            role2.Id = role2Id;

            var role3 = CreateTestRole("role3");
            role3.NormalizedName = "role3";
            role3.Id = role3Id;

            // create roles
            (await NewServiceScope().RoleStore.CreateAsync(role1)).Succeeded.Should()
                .BeTrue("because id does not exist yet");

            var role2Result = await NewServiceScope().RoleStore.CreateAsync(role2);
            role2Result.Succeeded.Should().BeFalse("because role with same id already exists");
            var codeToMatch = new IdentityErrorDescriber().DuplicateRoleName(role2.Name).Code;
            role2Result.Errors
                .Should()
                .Contain(error => error.Code == codeToMatch);

            (await NewServiceScope().RoleStore.CreateAsync(role3)).Succeeded.Should()
                .BeTrue("because id does not exist yet");

            WaitForUserToContinueTheTest(NewServiceScope().DocumentStore);
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldNotUpdateRoleNameIfAlreadyExistsWhenUsingStoreDirectly()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            var role = CreateTestRole("role");
            var role2 = CreateTestRole("role2");

            (await manager.CreateAsync(role)).Succeeded.Should().BeTrue();
            (await manager.CreateAsync(role2)).Succeeded.Should().BeTrue();

            var store = scope.RoleStore;

            await store.SetRoleNameAsync(role, role2.Name);
            await store.SetNormalizedRoleNameAsync(role, role2.NormalizedName);
            (await store.UpdateAsync(role))
                .Succeeded
                .Should()
                .BeFalse("because role2 name is already reserved for role2");
            WaitForUserToContinueTheTest(scope.DocumentStore);
        }

        /// <summary>
        /// This test is important to test the Store level uniqueness checks.
        /// Manager does internal validation against the indexes which we want to bypass here.
        /// </summary>
        /// <returns>A <see cref="Task"/> representing the asynchronous unit test.</returns>
        [Fact]
        public async Task ShouldUpdateRoleNameIfNotExistsAndAddNewRoleWithOldNameWhenUsingStoreDirectly()
        {
            var scope = NewServiceScope();
            var store = scope.RoleStore;

            const string initialRoleName = "roleToBeUpdated";

            var role1 = CreateTestRole(initialRoleName);
            role1.NormalizedName = initialRoleName;

            var role2 = CreateTestRole(initialRoleName);
            role2.NormalizedName = initialRoleName;

            // create roles
            (await store.CreateAsync(role1)).Succeeded.Should().BeTrue("because name is not reserved yet");
            (await NewServiceScope().RoleStore.CreateAsync(role2)).Succeeded.Should()
                .BeFalse("because role1 reserved the name");

            // update role 1
            await store.SetRoleNameAsync(role1, "someOtherName");
            await store.SetNormalizedRoleNameAsync(role1, "someOtherName");
            (await store.UpdateAsync(role1))
                .Succeeded
                .Should()
                .BeTrue("because new name does not exist yet");

            WaitForUserToContinueTheTest(scope.DocumentStore);

            (await store.FindByNameAsync("someOtherName")).Should().NotBeNull("because we updated the name");

            // create role2
            (await NewServiceScope().RoleStore.CreateAsync(role2)).Succeeded.Should()
                .BeTrue("because initial name is free again to use");
        }

        [Fact]
        public async Task ShouldFindExistingRoleByIdUsingManager()
        {
            var scope = NewServiceScope();
            var manager = scope.RoleManager;

            var role = CreateTestRole();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(role));

            RavenIdentityRole searchResult = await manager.FindByIdAsync(role.Id);
            searchResult.Should().NotBeNull();
            searchResult.Id.Should().Be(role.Id);

            // lets have it try with a new di scope
            var managerScope2 = NewServiceScope().RoleManager;
            searchResult = await managerScope2.FindByIdAsync(role.Id);
            searchResult.Should().NotBeNull();
            searchResult.Id.Should().Be(role.Id);
        }

        [Fact]
        public async Task ShouldAddNewClaimToRoleUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim(new Claim("type1", "value1")));
            role.AddClaim(new RavenIdentityClaim(new Claim("type1", "value2")));
            var claim = new RavenIdentityClaim(new Claim("type2", "value1"));
            role.AddClaim(claim);
            role.AddClaim(claim); // add duplicate claim

            (await NewServiceScope().RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();

            var roleRetrieved = await NewServiceScope().RoleManager.FindByIdAsync(role.Id);
            roleRetrieved.Should().NotBeNull();
            roleRetrieved
                .Should()
                .NotBeSameAs(role, "because we are using 2 different unit of works to handle the objects");
            roleRetrieved.Claims.Should().NotBeNull();
            roleRetrieved.Claims.Count.Should().Be(3);
            roleRetrieved.Claims
                .FirstOrDefault(cl => cl.Type == "type1" && cl.Value == "value1")
                .Should()
                .NotBeNull("because type1 value1 exists");
            roleRetrieved.Claims
                .FirstOrDefault(cl => cl.Type == "type1" && cl.Value == "value2")
                .Should()
                .NotBeNull("because type1 value2 exists");
            roleRetrieved.Claims
                .FirstOrDefault(cl => cl.Type == "type2" && cl.Value == "value1")
                .Should()
                .NotBeNull("because type2 value1 exists");

            WaitForUserToContinueTheTest(NewServiceScope().DocumentStore);
        }

        [Fact]
        public async Task ShouldNotAddRoleIfOtherWithSameNameExistsUsingManager()
        {
            var role1 = CreateTestRole("roleName");
            (await NewServiceScope().RoleManager.CreateAsync(role1)).Succeeded.Should().BeTrue();

            var role2 = CreateTestRole("roleName");
            role2.Id.Should().NotBe(role1.Id);
            var result = await NewServiceScope().RoleManager.CreateAsync(role2);
            result.Succeeded.Should().BeFalse();
            var expectedErrorCodeDuplicate = new IdentityErrorDescriber().DuplicateRoleName(role2.Name).Code;
            var expectedErrorCode2Concurrency = new IdentityErrorDescriber().ConcurrencyFailure().Code;
            result.Errors
                .Should()
                .Contain(error => error.Code == expectedErrorCodeDuplicate
                                  || error.Code == expectedErrorCode2Concurrency);
        }

        [Fact]
        public async Task ShouldNotUpdateIfEntityUpdatedOnServerUsingManger()
        {
            var role = CreateTestRole();
            var manager1 = NewServiceScope().RoleManager;
            await manager1.CreateAsync(role);

            var manager2 = NewServiceScope().RoleManager;
            var roleRetrieved = await manager2.FindByIdAsync(role.Id);

            await manager1.AddClaimAsync(role, new Claim("foo", "bar"));

            var result = await manager2.AddClaimAsync(roleRetrieved, new Claim("bar", "baz"));
            result.Succeeded.Should().BeFalse("manager1 already updated the entity from another session");
            var expectedErrorCode2Concurrency = new IdentityErrorDescriber().ConcurrencyFailure().Code;
            result.Errors
                .Should()
                .Contain(error => error.Code == expectedErrorCode2Concurrency);

            WaitForUserToContinueTheTest(NewServiceScope().DocumentStore);
        }

        [Fact]
        public async Task ShouldNotDeleteIfEntityUpdatedOnServerUsingManger()
        {
            var role = CreateTestRole();
            var manager1 = NewServiceScope().RoleManager;
            await manager1.CreateAsync(role);

            var manager2 = NewServiceScope().RoleManager;
            var roleRetrieved = await manager2.FindByIdAsync(role.Id);

            await manager1.AddClaimAsync(role, new Claim("foo", "bar"));

            var result = await manager2.DeleteAsync(roleRetrieved);
            result.Succeeded.Should().BeFalse("manager1 already updated the entity from another session");
            var expectedErrorCode2Concurrency = new IdentityErrorDescriber().ConcurrencyFailure().Code;
            result.Errors
                .Should()
                .Contain(error => error.Code == expectedErrorCode2Concurrency);

            WaitForUserToContinueTheTest(NewServiceScope().DocumentStore);
        }

        [Fact]
        public async Task ShouldAddMultipleRoleClaimsWithTheSameTypeButDifferentValuesUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim("type1", "value1"));
            role.AddClaim(new RavenIdentityClaim("type1", "value2"));
            role.AddClaim(new RavenIdentityClaim("type1", "value3"));
            role.AddClaim(new RavenIdentityClaim("type2", "value1"));

            // add duplicate just to make sure we ignore them
            role.AddClaim(new RavenIdentityClaim("type2", "value1"));

            var scope = NewServiceScope();
            (await scope.RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
            WaitForIndexing(scope.DocumentStore);

            var retrievedRole = await NewServiceScope().RoleManager.FindByNameAsync(role.Name);
            retrievedRole.Should().NotBeNull();
            retrievedRole.Claims.Should().NotBeNull();
            retrievedRole.Claims.Count.Should().Be(4);
            retrievedRole.Claims
                .FirstOrDefault(cl => cl.Type == "type1" && cl.Value == "value1")
                .Should()
                .NotBeNull();
            retrievedRole.Claims
                .FirstOrDefault(cl => cl.Type == "type1" && cl.Value == "value2")
                .Should()
                .NotBeNull();
            retrievedRole.Claims
                .FirstOrDefault(cl => cl.Type == "type1" && cl.Value == "value3")
                .Should()
                .NotBeNull();
            retrievedRole.Claims
                .FirstOrDefault(cl => cl.Type == "type2" && cl.Value == "value1")
                .Should()
                .NotBeNull();
        }

        [Fact]
        public async Task ShouldUpdateClaimsOnExistingRoleUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim("type1", "value1"));
            role.AddClaim(new RavenIdentityClaim("type2", "value1"));

            var scope1 = NewServiceScope();
            var manager1 = scope1.RoleManager;
            (await manager1.CreateAsync(role)).Succeeded.Should().BeTrue();

            var manager2 = NewServiceScope().RoleManager;
            var retrievedRole = await manager2.FindByIdAsync(role.Id);
            retrievedRole.Should().NotBeNull();

            retrievedRole.AddClaim(new RavenIdentityClaim("type99", "99"));
            retrievedRole.AddClaim(new RavenIdentityClaim("type99", "99b"));

            (await manager2.UpdateAsync(retrievedRole)).Succeeded.Should().BeTrue();
            WaitForIndexing(scope1.DocumentStore);

            var manager3 = NewServiceScope().RoleManager;
            retrievedRole = await manager3.FindByNameAsync(role.Name);
            retrievedRole.Should().NotBeNull();
            retrievedRole.Claims.Count.Should().Be(4);

            retrievedRole.RemoveClaim("type1", "value1");
            await manager3.UpdateAsync(retrievedRole);

            retrievedRole = await NewServiceScope().RoleManager.FindByIdAsync(role.Id);
            retrievedRole.Should().NotBeNull();
            retrievedRole.Claims.Count.Should().Be(3);
            retrievedRole.HasClaim(new RavenIdentityClaim("type1", "value1")).Should().BeFalse();
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnCreateWhenAutoSaveIsFalseUsingManager()
        {
            var scope = NewServiceScope();
            var roleStore = scope.RoleStore;
            roleStore.AutoSaveChanges = false;

            var role = CreateTestRole("test");
            (await scope.RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();

            var retrievedFromDb = await NewServiceScope().RoleManager.FindByIdAsync(role.Id);
            retrievedFromDb.Should().BeNull("because store was configured not to save changes on create");
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnUpdateWhenAutoSaveIsFalseUsingManager()
        {
            var role = CreateTestRole("test");
            (await NewServiceScope().RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();

            var scope = NewServiceScope();
            var roleStore = scope.RoleStore;
            roleStore.AutoSaveChanges = false;

            RavenIdentityRole toBeUpdated = await scope.RoleManager.FindByIdAsync(role.Id);
            toBeUpdated.Should().NotBeNull();
            toBeUpdated.Claims.Count.Should().Be(0, "because we added no claims initially");
            toBeUpdated.AddClaim(new RavenIdentityClaim("a", "b"));
            (await scope.RoleManager.UpdateAsync(toBeUpdated)).Succeeded.Should().BeTrue();

            var retrievedFromDb = await NewServiceScope().RoleManager.FindByIdAsync(role.Id);
            retrievedFromDb.Should().NotBeNull();
            retrievedFromDb.Claims.Count.Should().Be(
                0,
                "because store was configured not to save changes on update"
            );
        }

        [Fact]
        public async Task ShouldNotSaveChangesOnDeleteWhenAutoSaveIsFalseUsingManager()
        {
            var role = CreateTestRole("test");
            (await NewServiceScope().RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();

            var scope = NewServiceScope();
            var roleStore = scope.RoleStore;
            roleStore.AutoSaveChanges = false;

            RavenIdentityRole toBeRemoved = await scope.RoleManager.FindByIdAsync(role.Id);
            toBeRemoved.Should().NotBeNull();
            (await scope.RoleManager.DeleteAsync(toBeRemoved)).Succeeded.Should().BeTrue();

            var retrievedFromDb = await NewServiceScope().RoleManager.FindByIdAsync(role.Id);
            retrievedFromDb.Should().NotBeNull("because store was configured not to save changes on delete");
        }

        [Fact]
        public async Task ShouldDeleteExistingRoleUsingManager()
        {
            var manager = NewServiceScope().RoleManager;

            // pre creat 3 roles
            (await manager.CreateAsync(CreateTestRole())).Succeeded.Should().BeTrue();
            (await manager.CreateAsync(CreateTestRole())).Succeeded.Should().BeTrue();
            (await manager.CreateAsync(CreateTestRole())).Succeeded.Should().BeTrue();

            var role = CreateTestRole("test");
            (await manager.CreateAsync(role)).Succeeded.Should().BeTrue();

            var manager2 = NewServiceScope().RoleManager;
            var retrievedRole = await manager2.FindByIdAsync(role.Id);
            retrievedRole.Should().NotBeNull();

            (await manager2.DeleteAsync(retrievedRole)).Succeeded.Should().BeTrue();

            WaitForUserToContinueTheTest(NewServiceScope().DocumentStore);

            await AssertReservationDocumentDoesNotExistAsync(
                UniqueReservationType.Role,
                role.NormalizedName
            );
        }

        [Fact]
        public async Task ShouldNotUpdateIfEntityAlreadyUpdatedInDatabaseUsingManager()
        {
            await NewServiceScope().RoleManager.CreateAsync(CreateTestRole("test"));
            WaitForIndexing(NewServiceScope().DocumentStore);

            // get in first session
            var manager = NewServiceScope().RoleManager;
            var role = await manager.FindByNameAsync("test");

            {
                // update in second session
                var manager2 = NewServiceScope().RoleManager;
                var toUpdateInBackground = await manager2.FindByIdAsync(role.Id);
                toUpdateInBackground.AddClaim(new RavenIdentityClaim("foo", "bar"));
                (await manager2.UpdateAsync(toUpdateInBackground)).Succeeded.Should().BeTrue();
            }


            role.AddClaim(new RavenIdentityClaim("baz", "baz"));
            var updateResult = await manager.UpdateAsync(role);
            updateResult.Succeeded.Should().BeFalse();
            updateResult.Errors
                .Should()
                .Contain(error => error.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
        }

        [Fact]
        public async Task ShouldNotDeleteIfEntityAlreadyUpdatedWithNewUniqueNameUsingClusterWideTransaction()
        {
            await NewServiceScope().RoleManager.CreateAsync(CreateTestRole("test"));
            WaitForIndexing(NewServiceScope().DocumentStore);

            // get in first session
            var manager = NewServiceScope().RoleManager;
            var role = await manager.FindByNameAsync("test");

            // update in second session
            var manager2 = NewServiceScope().RoleManager;
            var toUpdateInBackground = await manager2.FindByIdAsync(role.Id);
            toUpdateInBackground.Name = "new-name";
            (await manager2.UpdateAsync(toUpdateInBackground)).Succeeded.Should().BeTrue();

            var deleteResult = await manager.DeleteAsync(role);
            deleteResult.Succeeded.Should().BeFalse();
            deleteResult.Errors
                .Should()
                .Contain(error => error.Code == new IdentityErrorDescriber().ConcurrencyFailure().Code);
            (await NewServiceScope().RoleManager.FindByIdAsync(role.Id))
                .Should()
                .NotBeNull("because we failed deleting it");
        }

        [Fact]
        public async Task ShouldAddClaimsUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim("test", "test"));
            await NewServiceScope().RoleManager.CreateAsync(role);

            var scope = NewServiceScope();
            var retrievedFromDb = await scope.RoleManager.FindByIdAsync(role.Id);
            retrievedFromDb.Should().NotBeNull();
            retrievedFromDb.Claims.Should().NotBeNull();
            retrievedFromDb.Claims.Count.Should().Be(1);

            await scope.RoleManager.AddClaimAsync(retrievedFromDb, new Claim("test2", "test"));
            await scope.RoleManager.AddClaimAsync(retrievedFromDb, new Claim("test2", "test2"));

            var manager2 = NewServiceScope().RoleManager;
            var updated = await manager2.FindByIdAsync(role.Id);
            updated.Should().NotBeNull();

            var claims = await manager2.GetClaimsAsync(updated);
            claims.Should().NotBeNull();
            claims.Count.Should().Be(3);
            claims.Should().Contain(claim => claim.Type == "test" && claim.Value == "test");
            claims.Should().Contain(claim => claim.Type == "test2" && claim.Value == "test");
            claims.Should().Contain(claim => claim.Type == "test2" && claim.Value == "test2");
        }

        [Fact]
        public async Task ShouldGetClaimsUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim("test", "test"));
            role.AddClaim(new RavenIdentityClaim("test2", "test2"));
            await NewServiceScope().RoleManager.CreateAsync(role);

            var manager = NewServiceScope().RoleManager;
            var fromDb = await manager.FindByIdAsync(role.Id);
            fromDb.Should().NotBeNull();

            var claims = await manager.GetClaimsAsync(fromDb);
            claims.Should().NotBeNull();
            claims.Count.Should().Be(2);
            claims.Should().Contain(claim => claim.Type == "test" && claim.Value == "test");
            claims.Should().Contain(claim => claim.Type == "test2" && claim.Value == "test2");
        }

        [Fact]
        public async Task ShouldRemoveClaimsUsingManager()
        {
            var role = CreateTestRole();
            role.AddClaim(new RavenIdentityClaim("test", "test"));
            role.AddClaim(new RavenIdentityClaim("test2", "test2"));
            await NewServiceScope().RoleManager.CreateAsync(role);

            var scope = NewServiceScope();
            var retrievedFromDb = await scope.RoleManager.FindByIdAsync(role.Id);
            retrievedFromDb.Should().NotBeNull();
            retrievedFromDb.Claims.Should().NotBeNull();
            retrievedFromDb.Claims.Count.Should().Be(2);

            await scope.RoleManager.RemoveClaimAsync(retrievedFromDb, new Claim("test2", "test2"));

            var manager2 = NewServiceScope().RoleManager;
            var updated = await manager2.FindByIdAsync(role.Id);
            updated.Should().NotBeNull();

            var claims = await manager2.GetClaimsAsync(updated);
            claims.Should().NotBeNull();
            claims.Count.Should().Be(1);
            claims.Should().Contain(claim => claim.Type == "test" && claim.Value == "test");
        }

        [Fact]
        public async Task ShouldAddNewRoleAfterRoleWithSameNameWasDeletedUsingManager()
        {
            var scope = NewServiceScope();
            var role = CreateTestRole("role");
            (await scope.RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
            WaitForIndexing(scope.DocumentStore);

            var scope2 = NewServiceScope();
            RavenIdentityRole retrievedRole = await scope2.RoleManager.FindByNameAsync(role.Name);
            (await scope2.RoleManager.DeleteAsync(retrievedRole)).Succeeded.Should().BeTrue();
            WaitForIndexing(scope2.DocumentStore);

            var scope3 = NewServiceScope();
            (await scope3.RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
        }

        [Fact]
        public async Task ShouldNotDeleteRoleIfThereAreUsersAssignedToThatRole()
        {
            var scope = NewServiceScope();
            var role = CreateTestRole("role");
            (await scope.RoleManager.CreateAsync(role)).Succeeded.Should().BeTrue();

            WaitForIndexing(scope.DocumentStore);

            var user = CreateTestUser();
            (await scope.UserManager.CreateAsync(user)).Succeeded.Should().BeTrue();
            (await scope.UserManager.AddToRoleAsync(user, role.Name)).Succeeded.Should().BeTrue();

            WaitForIndexing(scope.DocumentStore);

            {
                var scope2 = NewServiceScope();
                var retrievedRole = await scope2.RoleManager.FindByIdAsync(role.Id);
                var deleteResult = await scope2.RoleManager.DeleteAsync(retrievedRole);
                deleteResult.Succeeded.Should().BeFalse("users are assigned to the role.");
            }

            (await scope.UserManager.RemoveFromRoleAsync(user, role.Name)).Succeeded.Should().BeTrue();

            WaitForIndexing(scope.DocumentStore);

            {
                var scope2 = NewServiceScope();
                var retrievedRole = await scope2.RoleManager.FindByIdAsync(role.Id);
                var deleteResult = await scope2.RoleManager.DeleteAsync(retrievedRole);
                deleteResult.Succeeded.Should().BeTrue("no users are assigned to this role");
            }
        }

        private ServiceScope NewServiceScope(bool requireUniqueEmail = false, bool protectPersonalData = false)
            => InitializeServices(
                options => options.UseReservationDocumentsForUniqueValues = true,
                requireUniqueEmail,
                protectPersonalData
            );
    }
}