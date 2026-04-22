using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;

/// <summary>
/// Represents a passkey credential for a user in the identity system.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/webauthn-3/#credential-record"/>.
/// </remarks>
public class RavenIdentityUserPasskey
{
    /// <summary>
    /// Gets the credential ID for this passkey.
    /// </summary>
    public virtual required byte[] CredentialId { get; set; }

    /// <summary>
    /// Gets additional data associated with this passkey.
    /// </summary>
    public virtual required IdentityPasskeyData Data { get; set; }

    /// <summary>
    /// Converts a <see cref="UserPasskeyInfo"/> instance into a <see cref="RavenIdentityUserPasskey"/> object.
    /// </summary>
    /// <param name="passkey">An instance of <see cref="UserPasskeyInfo"/> containing passkey information.</param>
    /// <returns>A new <see cref="RavenIdentityUserPasskey"/> object populated with data from the provided <paramref name="passkey"/>.</returns>
    public static RavenIdentityUserPasskey FromPasskeyInfo(UserPasskeyInfo passkey)
    {
        return new RavenIdentityUserPasskey
        {
            CredentialId = passkey.CredentialId,
            Data = new IdentityPasskeyData
            {
                PublicKey = passkey.PublicKey,
                Name = passkey.Name,
                CreatedAt = passkey.CreatedAt,
                Transports = passkey.Transports,
                SignCount = passkey.SignCount,
                IsUserVerified = passkey.IsUserVerified,
                IsBackupEligible = passkey.IsBackupEligible,
                IsBackedUp = passkey.IsBackedUp,
                AttestationObject = passkey.AttestationObject,
                ClientDataJson = passkey.ClientDataJson,
            },
        };
    }
}