using System;
using System.Collections.Generic;
using System.Linq;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;

/// <summary>
/// Class that represents the RavenDB Identity User.
/// </summary>
public class RavenIdentityUser : RavenIdentityUser<
    RavenIdentityClaim,
    RavenIdentityUserLogin,
    RavenIdentityToken,
    RavenIdentityUserPasskey>
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
    /// </summary>
    /// <param name="id">User id. When NULL RavenDb will assign HiLO value automatically on store.</param>
    /// <param name="username">Username.</param>
    public RavenIdentityUser(string? id, string username)
        : base(id, username)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
    /// </summary>
    /// <param name="id">User id. When NULL RavenDb will assign HiLO value automatically on store.</param>
    /// <param name="username">Username.</param>
    /// <param name="email">User email.</param>
    public RavenIdentityUser(string? id, string username, string email)
        : base(id, username, email)
    {
    }

    /// <summary>
    /// Required for object mapping.
    /// </summary>
    protected RavenIdentityUser()
    {
    }
}

/// <summary>
/// Class that represents the RavenDB Identity User.
/// </summary>
/// <typeparam name="TUserClaim">Type of user claim.</typeparam>
/// <typeparam name="TUserLogin">Type of user login.</typeparam>
/// <typeparam name="TUserToken">Type of user token.</typeparam>
/// <typeparam name="TUserPasskey">Type of user passkey.</typeparam>
public abstract class RavenIdentityUser<TUserClaim, TUserLogin, TUserToken, TUserPasskey>
    : IdentityUser<string>, IClaimsReader<TUserClaim>, IClaimsWriter<TUserClaim>, IEntity
    where TUserClaim : RavenIdentityClaim
    where TUserLogin : RavenIdentityUserLogin
    where TUserToken : RavenIdentityToken
    where TUserPasskey : RavenIdentityUserPasskey
{
    private HashSet<string> _roleIds = [];
    private List<TUserLogin> _logins = [];
    private List<TUserToken> _tokens = [];
    private List<TUserClaim> _claims = [];
    private List<TUserPasskey> _passkeys = [];

    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityUser{TUserClaim,TUserLogin,TUserToken,TUserPasskey}"/> class.
    /// </summary>
    /// <param name="id">User id. When NULL RavenDb will assign HiLO value automatically on store.</param>
    /// <param name="username">User's username.</param>
    /// <param name="email">User's email address.</param>
    protected RavenIdentityUser(string? id, string username, string email)
        : base(username)
    {
        Email = email;
        Id = id!;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
    /// </summary>
    /// <param name="id">User id. When NULL RavenDb will assign HiLO value automatically on store.</param>
    /// <param name="username">User's username.</param>
    protected RavenIdentityUser(string? id, string username)
        : base(username)
    {
        Id = id!;
    }

    /// <summary>
    /// Required for object mapping.
    /// </summary>
#pragma warning disable CS8618, CS9264
    protected RavenIdentityUser()
#pragma warning restore CS8618, CS9264
    {
    }

    /// <summary>
    /// Gets or sets the primary key for this user.
    /// </summary>
    public sealed override string Id { get; set; }

    /// <inheritdoc/>
    public sealed override string? Email { get; set; }

    /// <summary>
    /// The date and time at which the role was created.
    /// </summary>
    public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.Now;

    /// <inheritdoc/>
    public IReadOnlyList<TUserClaim> Claims
    {
        get => _claims.AsReadOnly();
        private set => _claims = [..value];
    }

    /// <inheritdoc/>
    IReadOnlyList<TUserClaim> IClaimsWriter<TUserClaim>.Claims
    {
        set => _claims = [..value];
    }

    /// <summary>
    /// List of role ids the user is assigned to.
    /// </summary>
    public IEnumerable<string> Roles
    {
        get => _roleIds.ToList().AsReadOnly();
        private set => _roleIds = [..value];
    }

    /// <summary>
    /// List of <see cref="UserLoginInfo"/> the user has.
    /// </summary>
    public IReadOnlyList<TUserLogin> Logins
    {
        get => _logins.AsReadOnly();
        private set => _logins = [..value];
    }

    /// <summary>
    /// List of <see cref="RavenIdentityToken"/> the user has.
    /// </summary>
    public IReadOnlyList<TUserToken> Tokens
    {
        get => _tokens.AsReadOnly();
        private set => _tokens = [..value];
    }

    /// <summary>
    /// List of <see cref="RavenIdentityUserPasskey"/> the user has.
    /// </summary>
    public IReadOnlyList<TUserPasskey> Passkeys
    {
        get => _passkeys.AsReadOnly();
        private set => _passkeys = [..value];
    }

    /// <summary>
    /// Checks if the user is assigned to a role identified by the provider role id.
    /// </summary>
    /// <param name="roleId">Role id to check assignment for.</param>
    /// <returns>True if user is assigned to the role identified by the provided role id, otherwise False.</returns>
    public virtual bool HasRole(string roleId)
    {
        ArgumentNullException.ThrowIfNull(roleId);
        return _roleIds.Contains(roleId);
    }

    /// <summary>
    /// Checks if the user has the given <see cref="UserLoginInfo"/>.
    /// </summary>
    /// <param name="userLogin">The <see cref="UserLoginInfo"/> we are looking for.</param>
    /// <returns>True if the user has the given <see cref="UserLoginInfo"/>.</returns>
    public virtual bool HasLogin(TUserLogin userLogin)
    {
        ArgumentNullException.ThrowIfNull(userLogin);

        return FindLogin(userLogin.LoginProvider, userLogin.ProviderKey) != null;
    }

    /// <summary>
    /// Get the user login if user has one that matches the given parameters.
    /// </summary>
    /// <param name="loginProvider">Login provider.</param>
    /// <param name="providerKey">Login provider key.</param>
    /// <returns><see cref="IdentityUserLogin{TKey}"/> that matches the given parameters or Null.</returns>
    public virtual TUserLogin? GetUserLogin(string loginProvider, string providerKey)
    {
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(providerKey);

        return FindLogin(loginProvider, providerKey);
    }

    /// <summary>
    /// Checks if the user has a given token.
    /// </summary>
    /// <param name="token">The token we are looking for.</param>
    /// <returns>True if the user has the given token.</returns>
    public virtual bool HasToken(TUserToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return FindToken(token.LoginProvider, token.Name) != null;
    }

    /// <summary>
    /// Gets the token if it exists, by given login provider and name.
    /// </summary>
    /// <param name="loginProvider">Login provider.</param>
    /// <param name="tokenName">Token name.</param>
    /// <returns><see cref="IdentityUserToken{TKey}"/> if it exists otherwise Null.</returns>
    public virtual TUserToken? GetToken(string loginProvider, string tokenName)
    {
        ArgumentNullException.ThrowIfNull(loginProvider);
        ArgumentNullException.ThrowIfNull(tokenName);

        return FindToken(loginProvider, tokenName);
    }

    /// <summary>
    /// Adds a new token if it does not exists, otherwise replaces the existing one.
    /// </summary>
    /// <param name="userToken">User token to add or use to replace an existing one.</param>
    internal virtual void AddOrReplaceToken(TUserToken userToken)
    {
        ArgumentNullException.ThrowIfNull(userToken);

        TUserToken? existingToken = FindToken(
            userToken.LoginProvider,
            userToken.Name
        );
        if (existingToken != null)
        {
            _tokens.Remove(existingToken);
        }

        _tokens.Add(userToken);
    }

    /// <summary>
    /// Removes users token identified by the given token.
    /// </summary>
    /// <param name="loginProvider">Login provider.</param>
    /// <param name="tokenName">Token name.</param>
    internal virtual void RemoveToken(string loginProvider, string tokenName)
    {
        TUserToken? existingToken = FindToken(loginProvider, tokenName);
        if (existingToken != null)
        {
            _tokens.Remove(existingToken);
        }
    }

    /// <summary>
    /// Assigns a role to the user.
    /// </summary>
    /// <param name="roleId">The role id we are assigning to the user.</param>
    internal virtual void AddRole(string roleId)
    {
        ArgumentNullException.ThrowIfNull(roleId);

        _roleIds.Add(roleId);
    }

    /// <summary>
    /// Removes a role assigned to the user.
    /// </summary>
    /// <param name="roleId">The role id to remove from the role assignments.</param>
    internal virtual void RemoveRole(string roleId)
    {
        ArgumentNullException.ThrowIfNull(roleId);

        _roleIds.Remove(roleId);
    }

    /// <summary>
    /// Adds a user login to the user.
    /// </summary>
    /// <param name="newUserLogin">User login we want to add.</param>
    internal virtual void AddLogin(TUserLogin newUserLogin)
    {
        ArgumentNullException.ThrowIfNull(newUserLogin);

        if (HasLogin(newUserLogin))
        {
            return;
        }

        _logins.Add(newUserLogin);
    }

    /// <summary>
    /// Removes the given user login from the user.
    /// </summary>
    /// <param name="userLoginToRemove">The user login to remove.</param>
    internal virtual void RemoveLogin(TUserLogin userLoginToRemove)
    {
        ArgumentNullException.ThrowIfNull(userLoginToRemove);

        RemoveLogin(userLoginToRemove.LoginProvider, userLoginToRemove.ProviderKey);
    }

    /// <summary>
    /// Removes the given user login from the user.
    /// </summary>
    /// <param name="loginProvider">Login provider.</param>
    /// <param name="providerKey">Provider key.</param>
    internal virtual void RemoveLogin(string loginProvider, string providerKey)
    {
        if (loginProvider == null)
        {
            throw new ArgumentNullException(nameof(loginProvider));
        }

        if (providerKey == null)
        {
            throw new ArgumentNullException(nameof(providerKey));
        }

        TUserLogin? existing = FindLogin(loginProvider, providerKey);
        if (existing != null)
        {
            _logins.Remove(existing);
        }
    }

    /// <summary>
    /// Adds a new passkey.
    /// </summary>
    /// <param name="passkey"></param>
    /// <exception cref="ArgumentException">When passkey already exists.</exception>
    internal void AddPasskey(TUserPasskey passkey)
    {
        ArgumentNullException.ThrowIfNull(passkey);
        TUserPasskey? existing = FindPasskey(passkey.CredentialId);
        if (existing is not null)
        {
            throw new ArgumentException("Adding new user passkey failed. Passkey already exists.");
        }

        _passkeys.Add(passkey);
    }

    /// <summary>
    /// Finds a passkey by credential id.
    /// </summary>
    /// <param name="credentialId"></param>
    /// <returns>Instance of <see cref="TUserPasskey"/> if found, otherwise Null.</returns>
    internal TUserPasskey? FindPasskey(byte[] credentialId)
    {
        return _passkeys.SingleOrDefault(p => p.CredentialId.SequenceEqual(credentialId));
    }

    /// <summary>
    /// Removes a passkey if it exists.
    /// </summary>
    /// <param name="credentialId"></param>
    internal void RemovePasskey(byte[] credentialId)
    {
        TUserPasskey? existingPassKey = FindPasskey(credentialId);
        if (existingPassKey is not null)
        {
            _passkeys.Remove(existingPassKey);
        }
    }

    /// <summary>
    /// Finds an existing user token if it exists.
    /// </summary>
    /// <param name="loginProvider">Login provider to search for.</param>
    /// <param name="tokenName">Token name to search for.</param>
    /// <returns>User token matching given parameters, otherwise Null.</returns>
    protected virtual TUserToken? FindToken(string loginProvider, string tokenName)
    {
        return _tokens.SingleOrDefault(existing =>
            existing.LoginProvider == loginProvider
            && existing.Name == tokenName
        );
    }

    /// <summary>
    /// Finds an existing user login if it exists.
    /// </summary>
    /// <param name="loginProvider">Login provider.</param>
    /// <param name="providerKey">Provider key.</param>
    /// <returns>User login that matches the given parameters otherwise Null.</returns>
    protected virtual TUserLogin? FindLogin(string loginProvider, string providerKey)
    {
        return _logins.SingleOrDefault(existing =>
            existing.LoginProvider == loginProvider && existing.ProviderKey == providerKey
        );
    }
}