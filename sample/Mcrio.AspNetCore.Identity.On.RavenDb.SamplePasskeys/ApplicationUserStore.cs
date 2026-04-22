using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Index;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.SamplePasskeys;

public sealed class ApplicationUserStore : RavenUserStore<ApplicationUser, RavenIdentityRole,
    ApplicationUserByClaimIndex,
    UsersByClaimIndexEntry>
{
    public ApplicationUserStore(
        IdentityDocumentSessionProvider identityDocumentSessionProvider,
        IdentityErrorDescriber describer,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<ApplicationUserStore> logger,
        UniqueValuesReservationOptions uniqueValuesReservationOptions)
        : base(identityDocumentSessionProvider, describer, optionsAccessor, logger, uniqueValuesReservationOptions)
    {
    }
}