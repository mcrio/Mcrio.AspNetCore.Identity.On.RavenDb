using System;
using System.Security.Claims;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;

/// <summary>
/// Class representing the claims a user or role can have.
/// </summary>
public class RavenIdentityClaim
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityClaim"/> class.
    /// </summary>
    /// <param name="claimType">Type of the claim.</param>
    /// <param name="claimValue">Value of the claim.</param>
    public RavenIdentityClaim(string claimType, string claimValue)
    {
        Type = claimType ?? throw new ArgumentNullException(nameof(claimType));
        Value = claimValue ?? throw new ArgumentNullException(nameof(claimValue));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityClaim"/> class.
    /// </summary>
    /// <param name="claim">Claim.</param>
    public RavenIdentityClaim(Claim claim)
        : this(claim.Type, claim.Value)
    {
    }

    /// <summary>
    /// Required for object mapping.
    /// </summary>
    /// ReSharper disable once UnusedMember.Local
#pragma warning disable CS8618, CS9264
    private RavenIdentityClaim()
#pragma warning restore CS8618, CS9264
    {
    }

    /// <summary>
    /// Gets the claim type for this claim.
    /// </summary>
    public string Type { get; private set; }

    /// <summary>
    /// Gets the claim value for this claim.
    /// </summary>
    public string Value { get; private set; }

    /// <summary>
    /// Constructs a new claim with the type and value.
    /// </summary>
    /// <returns>The <see cref="Claim"/> that was produced.</returns>
    public virtual Claim ToClaim()
    {
        return new Claim(Type, Value);
    }
}