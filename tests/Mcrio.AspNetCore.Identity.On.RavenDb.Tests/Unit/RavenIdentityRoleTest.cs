using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using FluentAssertions;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Xunit;
using static Mcrio.AspNetCore.Identity.RavenDb.Tests.Initializer;

namespace Mcrio.AspNetCore.Identity.RavenDb.Tests.Unit
{
    [SuppressMessage("ReSharper", "SA1600", Justification = "Suppress missing documentation warning for test.")]
    public class RavenIdentityRoleTest
    {
        [Fact]
        public void ShouldDetectExistingClaim()
        {
            var role = CreateTestRole();
            role.ClearClaims();
            role.Claims.Count.Should().Be(0, "because we cleared the claims.");

            var claim1 = new Claim("type1", "value1");
            var claim2 = new Claim("type1", "value2");
            var claim3 = new Claim("type2", "value1");
            var claim4 = new Claim("type2", "value2");

            role.HasClaim(claim1).Should().BeFalse("because claim was not added yet.");
            role.AddClaim(claim1);
            role.HasClaim(claim1).Should().BeTrue("because newly added claim exists.");
            role.Claims.Count.Should().Be(1);

            role.HasClaim(claim2).Should().BeFalse("because claim was not added yet.");
            role.AddClaim(claim2);
            role.HasClaim(claim2).Should().BeTrue("because newly added claim exists.");
            role.Claims.Count.Should().Be(2);

            role.HasClaim(claim3).Should().BeFalse("because claim was not added yet.");
            role.HasClaim(claim4).Should().BeFalse("because claim was not added yet.");

            role.AddClaim(claim3);
            role.AddClaim(claim4);
            role.Claims.Count.Should().Be(4);

            role.HasClaim(claim1).Should().BeTrue("because newly added claim exists.");
            role.HasClaim(claim2).Should().BeTrue("because newly added claim exists.");
            role.HasClaim(claim3).Should().BeTrue("because newly added claim exists.");
            role.HasClaim(claim4).Should().BeTrue("because newly added claim exists.");
        }

        [Fact]
        public void ShouldAddClaimOrReturnFalseIfAlreadyExists()
        {
            var role = CreateTestRole();
            role.ClearClaims();
            var newClaim = new Claim("type1", "value1");

            bool addNewResult = role.AddClaim(newClaim);
            addNewResult.Should().BeTrue("because we added a non existing claim.");

            bool addExistingResult = role.AddClaim(newClaim);
            addExistingResult.Should().BeFalse("because claim already exists.");
        }

        [Fact]
        public void ShouldRemoveClaimIfExistsOrIndicateFalseOtherwise()
        {
            var role = CreateTestRole();

            var claim1 = new Claim("type1", "value1");
            var claim2 = new Claim("type1", "value2");
            var claim3 = new Claim("type2", "value1");
            var claim4 = new Claim("type2", "value2");

            role.AddClaim(claim1);
            role.AddClaim(claim2);
            role.AddClaim(claim3);
            role.Claims.Count.Should().Be(3);

            role.RemoveClaim(claim4).Should().BeFalse("because claim does not exist in collection");
            role.RemoveClaim(claim1).Should().BeTrue("because claim was in collection");
            role.RemoveClaim(claim2).Should().BeTrue("because claim was in collection");
            role.RemoveClaim(claim3).Should().BeTrue("because claim was in collection");

            role.Claims.Count.Should().Be(0);
        }
    }
}