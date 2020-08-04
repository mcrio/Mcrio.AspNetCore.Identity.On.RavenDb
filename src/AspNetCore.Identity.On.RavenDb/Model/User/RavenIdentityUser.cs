using System;
using System.Collections.Generic;
using System.Linq;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User
{
    /// <summary>
    /// Class that represents the RavenDB Identity User.
    /// todo: check if Logins will be better of with a separate collection.
    /// </summary>
    public class RavenIdentityUser : RavenIdentityUser<string>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
        /// </summary>
        /// <param name="id">User ID.</param>
        /// <param name="username">Username.</param>
        public RavenIdentityUser(string id, string username)
            : base(id, username)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
        /// </summary>
        public RavenIdentityUser()
        {
        }
    }

    /// <summary>
    /// Class that represents the RavenDB Identity User.
    /// </summary>
    /// <typeparam name="TKey">Type of the Id property.</typeparam>
    public class RavenIdentityUser<TKey> : IdentityUser<TKey>, IClaimsReader, IClaimsWriter
        where TKey : IEquatable<TKey>
    {
        private HashSet<TKey> _roles = new HashSet<TKey>();
        private List<UserLoginInfo> _logins = new List<UserLoginInfo>();
        private List<RavenIdentityToken> _tokens = new List<RavenIdentityToken>();
        private List<RavenIdentityClaim> _claims = new List<RavenIdentityClaim>();

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityUser"/> class.
        /// </summary>
        /// <param name="id">User identifier.</param>
        /// <param name="username">Username.</param>
        public RavenIdentityUser(TKey id, string username)
            : base(username)
        {
            Id = id;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityUser{TKey}"/> class.
        /// </summary>
        /// <param name="id">User identifier.</param>
        /// <param name="username">User's username.</param>
        /// <param name="email">User's email address.</param>
        public RavenIdentityUser(TKey id, string username, string email)
            : this(id, username)
        {
            Email = email;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityUser{TKey}"/> class.
        /// </summary>
        public RavenIdentityUser()
        {
        }

        /// <inheritdoc/>
        public sealed override TKey Id { get; set; } = default!;

        /// <inheritdoc/>
        public sealed override string? Email { get; set; }

        /// <summary>
        /// The date and time at which the role was created.
        /// </summary>
        public DateTimeOffset CreatedAt { get; private set; } = DateTimeOffset.Now;

        /// <inheritdoc/>
        public IReadOnlyList<RavenIdentityClaim> Claims => _claims.AsReadOnly();

        /// <inheritdoc/>
        IReadOnlyList<RavenIdentityClaim> IClaimsWriter.Claims
        {
            set => _claims = new List<RavenIdentityClaim>(value);
        }

        /// <summary>
        /// List of role ids the user is assigned to.
        /// </summary>
        public IEnumerable<TKey> Roles
        {
            get => _roles.ToList().AsReadOnly();
            private set => _roles = new HashSet<TKey>(value);
        }

        /// <summary>
        /// List of <see cref="UserLoginInfo"/> the user has.
        /// </summary>
        public IReadOnlyList<UserLoginInfo> Logins
        {
            get => _logins.AsReadOnly();
            private set => _logins = new List<UserLoginInfo>(value);
        }

        /// <summary>
        /// List of <see cref="RavenIdentityToken"/> the user has.
        /// </summary>
        public IReadOnlyList<RavenIdentityToken> Tokens
        {
            get => _tokens.AsReadOnly();
            private set => _tokens = new List<RavenIdentityToken>(value);
        }

        /// <summary>
        /// Checks if the user is assigned to a role identified by the provider role id.
        /// </summary>
        /// <param name="roleId">Role id to check assignment for.</param>
        /// <returns>True if user is assigned to the role identified by the provided role id, otherwise False.</returns>
        public bool HasRole(TKey roleId)
        {
            if (roleId is null)
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            return _roles.Contains(roleId);
        }

        /// <summary>
        /// Checks if the user has the given <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> we are looking for.</param>
        /// <returns>True if the user has the given <see cref="UserLoginInfo"/>.</returns>
        public bool HasLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo is null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }

            return HasLogin(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey);
        }

        /// <summary>
        /// Checks if the user has the given <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Provider key.</param>
        /// <returns>True if the user has a login matching the given parameters.</returns>
        public bool HasLogin(string loginProvider, string providerKey)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            return FindLogin(loginProvider, providerKey) != null;
        }

        /// <summary>
        /// Get the user login if user has one that matches the given parameters.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Login provider key.</param>
        /// <returns><see cref="IdentityUserLogin{TKey}"/> that matches the given parameters or Null.</returns>
        public IdentityUserLogin<TKey>? GetUserLogin(string loginProvider, string providerKey)
        {
            if (loginProvider is null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            UserLoginInfo? existingLogin = FindLogin(loginProvider, providerKey);
            if (existingLogin != null)
            {
                return new IdentityUserLogin<TKey>
                {
                    UserId = Id,
                    LoginProvider = existingLogin.LoginProvider,
                    ProviderDisplayName = existingLogin.ProviderDisplayName,
                    ProviderKey = existingLogin.ProviderKey,
                };
            }

            return null;
        }

        /// <summary>
        /// Checks if the user has a given token.
        /// </summary>
        /// <param name="token">The token we are looking for.</param>
        /// <returns>True if the user has the given token.</returns>
        public bool HasToken(IdentityUserToken<TKey> token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return FindToken(token.LoginProvider, token.Name) != null;
        }

        /// <summary>
        /// Gets the token if it exists, by given login provider and name.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="tokenName">Token name.</param>
        /// <returns><see cref="IdentityUserToken{TKey}"/> if it exists otherwise Null.</returns>
        public IdentityUserToken<TKey>? GetToken(string loginProvider, string tokenName)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            RavenIdentityToken? token = FindToken(loginProvider, tokenName);
            if (token is null)
            {
                return null;
            }

            return new IdentityUserToken<TKey>
            {
                UserId = Id,
                LoginProvider = token.LoginProvider,
                Name = token.Name,
                Value = token.Value,
            };
        }

        /// <summary>
        /// Sets a new value for an existing token identified by given login provider and token name.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="tokenName">Token name.</param>
        /// <param name="value">New token value.</param>
        internal void AddOrUpdateToken(string loginProvider, string tokenName, string value)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            RavenIdentityToken? existingToken = FindToken(loginProvider, tokenName);
            if (existingToken != null)
            {
                existingToken.Value = value;
            }
            else
            {
                _tokens.Add(new RavenIdentityToken(loginProvider, tokenName, value));
            }
        }

        /// <summary>
        /// Removes users token identified by the given token.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="tokenName">Token name.</param>
        internal void RemoveToken(string loginProvider, string tokenName)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (tokenName == null)
            {
                throw new ArgumentNullException(nameof(tokenName));
            }

            RavenIdentityToken? existingToken = FindToken(loginProvider, tokenName);
            if (existingToken != null)
            {
                _tokens.Remove(existingToken);
            }
        }

        /// <summary>
        /// Assigns a role to the user.
        /// </summary>
        /// <param name="roleId">The role id we are assigning to the user.</param>
        internal void AddRole(TKey roleId)
        {
            if (roleId is null)
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            _roles.Add(roleId);
        }

        /// <summary>
        /// Removes a role assigned to the user.
        /// </summary>
        /// <param name="roleId">The role id to remove from the role assignments.</param>
        internal void RemoveRole(TKey roleId)
        {
            if (roleId is null)
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            _roles.Remove(roleId);
        }

        /// <summary>
        /// Adds a <see cref="UserLoginInfo"/> to the user.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> we want to add.</param>
        internal void AddLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo is null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }

            if (HasLogin(userLoginInfo))
            {
                return;
            }

            _logins.Add(userLoginInfo);
        }

        /// <summary>
        /// Removes the given <see cref="UserLoginInfo"/> from the user.
        /// </summary>
        /// <param name="userLoginInfo">The <see cref="UserLoginInfo"/> to remove.</param>
        internal void RemoveLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo is null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }

            RemoveLogin(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey);
        }

        /// <summary>
        /// Removes the given <see cref="UserLoginInfo"/> from the user.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Provider key.</param>
        internal void RemoveLogin(string loginProvider, string providerKey)
        {
            if (string.IsNullOrWhiteSpace(loginProvider))
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (string.IsNullOrWhiteSpace(providerKey))
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            UserLoginInfo? existing = FindLogin(loginProvider, providerKey);
            if (existing != null)
            {
                _logins.Remove(existing);
            }
        }

        private RavenIdentityToken? FindToken(string loginProvider, string tokenName)
        {
            return _tokens.SingleOrDefault(existing =>
                existing.LoginProvider == loginProvider
                && existing.Name == tokenName
            );
        }

        private UserLoginInfo? FindLogin(string loginProvider, string providerKey)
        {
            return _logins.SingleOrDefault(existing =>
                existing.LoginProvider == loginProvider && existing.ProviderKey == providerKey
            );
        }
    }
}