using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.SamplePasskeys;

public sealed class ApplicationRoleStore
    : RavenRoleStore<RavenIdentityRole, ApplicationUser>
{
    public ApplicationRoleStore(
        IdentityDocumentSessionProvider documentSessionProvider,
        IdentityErrorDescriber errorDescriber,
        ILogger<ApplicationRoleStore> logger,
        UniqueValuesReservationOptions uniqueValuesReservationOptions)
        : base(documentSessionProvider, errorDescriber, logger, uniqueValuesReservationOptions)
    {
    }
}