using System.Linq;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Raven.Client.Documents.Indexes;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Index;

/// <inheritdoc />
public class UsersByClaimIndex : UsersByClaimIndex<RavenIdentityUser>;

/// <inheritdoc />
public abstract class UsersByClaimIndex<TUser>
    : UsersByClaimIndex<TUser, RavenIdentityClaim, RavenIdentityUserLogin, RavenIdentityToken, RavenIdentityUserPasskey>
    where TUser : RavenIdentityUser;

/// <summary>
/// User claims static fan-out index. This static index is required as the RavenDB Corax search engine does not support
/// `intersect` queries and there are scenarios where we need to lookup collection child properties by multiple fields.
/// https://issues.hibernatingrhinos.com/issue/RavenDB-19777/Support-Intersect-queries-in-Corax .
/// </summary>
/// <typeparam name="TUser">Identity user type.</typeparam>
/// <typeparam name="TUserClaim">Identity user claim type.</typeparam>
/// <typeparam name="TUserLogin">Identity user login type.</typeparam>
/// <typeparam name="TUserToken">Identity user token type.</typeparam>
/// <typeparam name="TUserPasskey">Identity user passkey type.</typeparam>
public abstract class
    UsersByClaimIndex<TUser, TUserClaim, TUserLogin, TUserToken, TUserPasskey> : AbstractIndexCreationTask<TUser>
    where TUser : RavenIdentityUser<TUserClaim, TUserLogin, TUserToken, TUserPasskey>
    where TUserClaim : RavenIdentityClaim
    where TUserToken : RavenIdentityToken
    where TUserLogin : RavenIdentityUserLogin
    where TUserPasskey : RavenIdentityUserPasskey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UsersByClaimIndex{TUser,TUserClaim,TUserLogin,TUserToken,TUserPasskey}"/> class.
    /// </summary>
    protected UsersByClaimIndex()
    {
        Map = users => from user in users
            from claim in user.Claims
            select new UsersByClaimIndexEntry
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value,
            };
    }
}

/// <summary>
/// Users by claim index entry properties.
/// </summary>
public class UsersByClaimIndexEntry
{
    /// <summary>
    /// Gets or sets the claim type.
    /// </summary>
    public required string ClaimType { get; set; }

    /// <summary>
    /// Gets or sets the claim value.
    /// </summary>
    public required string ClaimValue { get; set; }
}