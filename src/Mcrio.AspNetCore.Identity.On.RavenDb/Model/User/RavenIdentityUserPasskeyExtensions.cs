using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;

/// <summary>
/// Extension methods for <see cref="RavenIdentityUserPasskey"/>.
/// </summary>
internal static class RavenIdentityUserPasskeyExtensions
{
    extension(RavenIdentityUserPasskey passkey)
    {
        public void UpdateFromUserPasskeyInfo(UserPasskeyInfo passkeyInfo)
        {
            // We only mutate properties that can be updated after passkey creation.
            // See https://www.w3.org/TR/webauthn-3/#authn-ceremony-update-credential-record
            passkey.Data.Name = passkeyInfo.Name;
            passkey.Data.SignCount = passkeyInfo.SignCount;
            passkey.Data.IsBackedUp = passkeyInfo.IsBackedUp;
            passkey.Data.IsUserVerified = passkeyInfo.IsUserVerified;
        }

        public UserPasskeyInfo ToUserPasskeyInfo()
            => new (
                passkey.CredentialId,
                passkey.Data.PublicKey,
                passkey.Data.CreatedAt,
                passkey.Data.SignCount,
                passkey.Data.Transports,
                passkey.Data.IsUserVerified,
                passkey.Data.IsBackupEligible,
                passkey.Data.IsBackedUp,
                passkey.Data.AttestationObject,
                passkey.Data.ClientDataJson)
            {
                Name = passkey.Data.Name,

                // todo this is coming in a later version
                /*Aaguid = passkey.Data.Aaguid,*/
            };
    }
}