using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Mcrio.AspNetCore.Identity.RavenDb.Model;
using Mcrio.AspNetCore.Identity.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.RavenDb.Model.User;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Raven.Client.Documents;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;

namespace Mcrio.AspNetCore.Identity.RavenDb
{
    /// <inheritdoc />
    public class RavenUserStore : RavenUserStore<RavenIdentityUser, RavenIdentityRole, string>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        public RavenUserStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore> logger)
            : base(documentSession, describer, optionsAccessor, logger)
        {
        }
    }

    /// <inheritdoc />
    public class RavenUserStore<TUser, TRole, TKey> : RavenUserStore<TUser, TRole, TKey, IdentityUserClaim<TKey>,
        IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>
        where TUser : RavenIdentityUser<TKey>
        where TRole : RavenIdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser, TRole, TKey}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        public RavenUserStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TRole, TKey>> logger)
            : base(documentSession, describer, optionsAccessor, logger)
        {
        }
    }

    /// <inheritdoc />
    public class RavenUserStore<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
        UserStoreBase<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>
        where TUser : RavenIdentityUser<TKey>
        where TRole : RavenIdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserToken : IdentityUserToken<TKey>, new()
        where TRoleClaim : IdentityRoleClaim<TKey>, new()
    {
        protected readonly IAsyncDocumentSession DocumentSession;
        protected readonly IOptions<IdentityOptions> OptionsAccessor;

        protected readonly
            ILogger<RavenUserStore<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>>
            Logger;

        /// <summary>
        /// User properties that may require unique value.
        /// </summary>
        protected enum UniqueUserPropertyChangeType
        {
            /// <summary>
            /// Username property unique value change.
            /// </summary>
            Username,

            /// <summary>
            /// Email property unique value change.
            /// </summary>
            Email,
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        public RavenUserStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>>
                logger)
            : base(describer)
        {
            DocumentSession = documentSession ?? throw new ArgumentNullException(nameof(documentSession));
            OptionsAccessor = optionsAccessor;
            Logger = logger;
        }

        /// <inheritdoc/>
        public override IQueryable<TUser> Users => DocumentSession.Query<TUser>();

        /// <summary>
        /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
        /// </summary>
        /// <value>
        /// True if changes should be automatically persisted, otherwise false.
        /// </value>
        public virtual bool AutoSaveChanges { get; set; } = true;

        /// <summary>
        /// Creates a new user.
        /// </summary>
        /// <param name="user">User to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task<IdentityResult> CreateAsync(
            TUser user,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(user.UserName))
            {
                throw new ArgumentNullException(nameof(user.UserName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            // Reserve username
            bool usernameReservationResult = await DocumentSession.CreateReservationAsync<string>(
                RavenDbCompareExchangeExtension.ReservationType.Username,
                user.NormalizedUserName
            ).ConfigureAwait(false);
            if (!usernameReservationResult)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            // reserve email if unique email required
            var emailReservationResult = false;
            if (OptionsAccessor.Value.User.RequireUniqueEmail)
            {
                if (string.IsNullOrWhiteSpace(user.NormalizedEmail))
                {
                    throw new ArgumentNullException(nameof(user.NormalizedEmail));
                }

                emailReservationResult = await DocumentSession.CreateReservationAsync<string>(
                    RavenDbCompareExchangeExtension.ReservationType.Email,
                    user.NormalizedEmail
                ).ConfigureAwait(false);
                if (!emailReservationResult)
                {
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Username,
                        user.NormalizedUserName
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing username '{user.NormalizedUserName}' from compare exchange "
                        );
                    }

                    return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
                }
            }

            var saveSuccess = false;
            try
            {
                await DocumentSession
                    .StoreAsync(user, string.Empty, user.Id.ToString(), cancellationToken)
                    .ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
                return IdentityResult.Success;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed creating user {}", ex.Message);
                return IdentityResult.Failed(ErrorDescriber.DefaultError());
            }
            finally
            {
                if (!saveSuccess)
                {
                    // remove username reservations
                    bool removeUsernameCmpE = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Username,
                        user.NormalizedUserName
                    ).ConfigureAwait(false);
                    if (!removeUsernameCmpE)
                    {
                        Logger.LogError(
                            $"Failed removing username '{user.NormalizedUserName}' from compare exchange "
                        );
                    }

                    if (emailReservationResult)
                    {
                        // remove email reservations
                        bool removeEmailCmpE = await DocumentSession.RemoveReservationAsync(
                            RavenDbCompareExchangeExtension.ReservationType.Email,
                            user.NormalizedEmail!
                        ).ConfigureAwait(false);
                        if (!removeEmailCmpE)
                        {
                            Logger.LogError(
                                $"Failed removing email '{user.NormalizedEmail}' from compare exchange "
                            );
                        }
                    }
                }
            }
        }

        /// <inheritdoc/>
        public override async Task<IdentityResult> UpdateAsync(
            TUser user,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            if (!DocumentSession.Advanced.IsLoaded(user.Id.ToString()))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            // if username has changed, and if yes make sure it's unique by reserving it
            PropertyChange<string>? normalizedUsernameChange = null;

            // if email has changed and if we require unique emails
            PropertyChange<string>? normalizedEmailChange = null;

            var changeVector = DocumentSession.Advanced.GetChangeVectorFor(user);

            var saveSuccess = false;
            try
            {
                normalizedUsernameChange = await ReserveIfUserPropertyChangedAsync(
                    user,
                    UniqueUserPropertyChangeType.Username
                ).ConfigureAwait(false);

                if (OptionsAccessor.Value.User.RequireUniqueEmail)
                {
                    normalizedEmailChange = await ReserveIfUserPropertyChangedAsync(
                        user,
                        UniqueUserPropertyChangeType.Email
                    ).ConfigureAwait(false);
                }

                await DocumentSession.StoreAsync(user, changeVector, user.Id.ToString(), cancellationToken)
                    .ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
            }
            catch (UniqueValueExistsException ex)
            {
                Logger.LogInformation(ex, $"Failed reserving unique value: {ex.Message}");
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed updating user {} {}", user.UserName, ex.Message);
                return IdentityResult.Failed(ErrorDescriber.DefaultError());
            }
            finally
            {
                if (normalizedUsernameChange != null)
                {
                    var usernameReservationToRemove = saveSuccess
                        ? normalizedUsernameChange.OldValue
                        : normalizedUsernameChange.NewValue;
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Username,
                        usernameReservationToRemove
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing username '{usernameReservationToRemove}' from compare exchange "
                        );
                    }
                }

                if (normalizedEmailChange != null)
                {
                    var emailReservationToRemove = saveSuccess
                        ? normalizedEmailChange.OldValue
                        : normalizedEmailChange.NewValue;
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Email,
                        emailReservationToRemove
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing email '{emailReservationToRemove}' from compare exchange "
                        );
                    }
                }
            }

            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes the given user.
        /// </summary>
        /// <param name="user">User to be deleted.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task<IdentityResult> DeleteAsync(
            TUser user,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            if (!DocumentSession.Advanced.IsLoaded(user.Id.ToString()))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            var changeVector = DocumentSession.Advanced.GetChangeVectorFor(user);

            var saveSuccess = false;
            try
            {
                DocumentSession.Delete(user.Id.ToString(), changeVector);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed deleting user {} {}", user.UserName, ex.Message);
                return IdentityResult.Failed(ErrorDescriber.DefaultError());
            }
            finally
            {
                if (saveSuccess)
                {
                    // remove username reservations
                    bool removeUsernameCmpE = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Username,
                        user.NormalizedUserName
                    ).ConfigureAwait(false);
                    if (!removeUsernameCmpE)
                    {
                        Logger.LogError(
                            $"Failed removing username '{user.NormalizedUserName}' from compare exchange "
                        );
                    }

                    if (OptionsAccessor.Value.User.RequireUniqueEmail)
                    {
                        // remove email reservations
                        bool removeEmailCmpE = await DocumentSession.RemoveReservationAsync(
                            RavenDbCompareExchangeExtension.ReservationType.Email,
                            user.NormalizedEmail!
                        ).ConfigureAwait(false);
                        if (!removeEmailCmpE)
                        {
                            Logger.LogError(
                                $"Failed removing email '{user.NormalizedEmail}' from compare exchange "
                            );
                        }
                    }
                }
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            return DocumentSession.LoadAsync<TUser>(userId, cancellationToken);
        }

        /// <summary>
        /// Finds a user by given normalized username.
        /// </summary>
        /// <param name="normalizedUserName">Normalized username.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <exception cref="Exception">When there is more than one user matching the username.</exception>
        public override Task<TUser> FindByNameAsync(
            string normalizedUserName,
            CancellationToken cancellationToken = default)
        {
            if (normalizedUserName == null)
            {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession
                .Query<TUser>()
                .Where(user => user.NormalizedUserName == normalizedUserName)
                .SingleOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);
            return Task.FromResult<IList<Claim>>(user.Claims.Select(claim => claim.ToClaim()).ToList());
        }

        /// <inheritdoc/>
        public override Task AddClaimsAsync(
            TUser user,
            IEnumerable<Claim> claims,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            foreach (Claim claim in claims)
            {
                user.AddClaim(claim);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public override Task ReplaceClaimAsync(
            TUser user,
            Claim claim,
            Claim newClaim,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            user.ReplaceClaim(claim, newClaim);

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public override Task RemoveClaimsAsync(
            TUser user,
            IEnumerable<Claim> claims,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            foreach (Claim claim in claims)
            {
                user.RemoveClaim(claim);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public override async Task<IList<TUser>> GetUsersForClaimAsync(
            Claim claim,
            CancellationToken cancellationToken = default)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            // todo: AspNet Core by default does not implement pagination!!! let's set return count to 1000
            return await DocumentSession.Query<TUser>()
                .Where(user => user.Claims.Any(item => item.Type == claim.Type && item.Value == claim.Value))
                .Take(1000)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
        }

        /// <summary>
        /// Adds external login information to given user.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="login">User login data.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddLoginAsync(
            TUser user,
            UserLoginInfo login,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            if (user.HasLogin(login))
            {
                return;
            }

            bool loginReservation = await DocumentSession.CreateReservationAsync(
                RavenDbCompareExchangeExtension.ReservationType.Login,
                GetLoginReservationUniqueValue(login.LoginProvider, login.ProviderKey),
                user.Id.ToString()
            ).ConfigureAwait(false);

            if (!loginReservation)
            {
                return;
            }

            user.AddLogin(login);
        }

        /// <inheritdoc/>
        public override async Task RemoveLoginAsync(
            TUser user,
            string loginProvider,
            string providerKey,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(loginProvider))
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (string.IsNullOrWhiteSpace(providerKey))
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            if (!DocumentSession.Advanced.IsLoaded(user.Id.ToString()))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            var changeVector = DocumentSession.Advanced.GetChangeVectorFor(user);

            user.RemoveLogin(loginProvider, providerKey);

            var saveSuccess = false;
            try
            {
                await DocumentSession.StoreAsync(user, changeVector, user.Id.ToString(), cancellationToken);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
            }
            catch (ConcurrencyException)
            {
                Logger.LogInformation(
                    $"Failed removing login {loginProvider} for user {user.UserName} due do concurrency problem."
                );
            }
            finally
            {
                if (saveSuccess)
                {
                    bool removedLoginReservation = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Login,
                        GetLoginReservationUniqueValue(loginProvider, providerKey)
                    ).ConfigureAwait(false);

                    if (!removedLoginReservation)
                    {
                        Logger.LogError(
                            $"Failed removing login reservation {loginProvider} for user {user.UserName}."
                        );
                    }
                }
            }
        }

        /// <inheritdoc/>
        public override Task<IList<UserLoginInfo>> GetLoginsAsync(
            TUser user,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return Task.FromResult<IList<UserLoginInfo>>(new List<UserLoginInfo>(user.Logins));
        }

        /// <summary>
        /// Finds a user by the given email.
        /// </summary>
        /// <param name="normalizedEmail">Normalized email address.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <exception cref="Exception">When there is more than one user with the email.</exception>
        public override Task<TUser> FindByEmailAsync(
            string normalizedEmail,
            CancellationToken cancellationToken = default)
        {
            if (normalizedEmail == null)
            {
                throw new ArgumentNullException(nameof(normalizedEmail));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession
                .Query<TUser>()
                .Where(user => user.Email == normalizedEmail)
                .SingleOrDefaultAsync(token: cancellationToken);
        }

        /// <summary>
        /// Checks if the given user is assigned a role by the given role name.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="normalizedRoleName">Normalized role name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task<bool> IsInRoleAsync(
            TUser user,
            string normalizedRoleName,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            var role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            return role != null && user.HasRole(role.Id);
        }

        /// <inheritdoc/>
        public override async Task<IList<TUser>> GetUsersInRoleAsync(
            string normalizedRoleName,
            CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            ThrowIfCancelledOrDisposed(cancellationToken);

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (role is null)
            {
                throw new InvalidOperationException($"Unknown role with normalized name {normalizedRoleName}");
            }

            // todo: AspNet Core by default does not implement pagination!!! let's set return count to 1000
            return await DocumentSession.Query<TUser>()
                .Where(item => item.Roles.Any(roleId => roleId.Equals(role.Id)))
                .Take(1000)
                .ToListAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public override async Task AddToRoleAsync(
            TUser user,
            string normalizedRoleName,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (role is null)
            {
                throw new InvalidOperationException($"Unknown role with normalized name {normalizedRoleName}");
            }

            user.AddRole(role.Id);
        }

        /// <inheritdoc/>
        public override async Task RemoveFromRoleAsync(
            TUser user,
            string normalizedRoleName,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken);

            if (role is null)
            {
                throw new InvalidOperationException($"Unknown role with normalized name {normalizedRoleName}");
            }

            user.RemoveRole(role.Id);
        }

        /// <summary>
        /// Get the names of roles assigned to the given user.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task<IList<string>> GetRolesAsync(
            TUser user,
            CancellationToken cancellationToken = default)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            Dictionary<string, TRole> roles = await DocumentSession
                .LoadAsync<TRole>(user.Roles.Select(roleId => roleId.ToString()), cancellationToken)
                .ConfigureAwait(false);

            return roles.Values.Select(role => role.Name).ToList();
        }

        /// <inheritdoc/>
        public override Task SetTokenAsync(
            TUser user,
            string loginProvider,
            string name,
            string value,
            CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);
            return AddUserTokenAsync(CreateUserToken(user, loginProvider, name, value));
        }

        /// <summary>
        /// Find user token by given parameters.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="name">Token name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override Task<TUserToken> FindTokenAsync(
            TUser user,
            string loginProvider,
            string name,
            CancellationToken cancellationToken)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            return Task.FromResult((TUserToken)user.GetToken(loginProvider, name)!);
        }

        /// <summary>
        /// Adds token to the user.
        /// </summary>
        /// <param name="userToken">User token information.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task AddUserTokenAsync(TUserToken userToken)
        {
            TUser user = await DocumentSession.LoadAsync<TUser>(userToken.UserId.ToString());
            user?.AddOrUpdateToken(userToken.LoginProvider, userToken.Name, userToken.Value);
        }

        /// <summary>
        /// Removes token from the user.
        /// </summary>
        /// <param name="token">User token information.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task RemoveUserTokenAsync(TUserToken token)
        {
            TUser user = await DocumentSession.LoadAsync<TUser>(token.UserId.ToString());
            user?.RemoveToken(token.LoginProvider, token.Name);
        }

        protected virtual void ThrowIfCancelledOrDisposed(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            ThrowIfDisposed();
        }

        /// <summary>
        /// Saves the current store.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected virtual Task SaveChangesAsync(CancellationToken cancellationToken)
        {
            return AutoSaveChanges ? DocumentSession.SaveChangesAsync(cancellationToken) : Task.CompletedTask;
        }

        /// <inheritdoc/>
        protected override Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession.LoadAsync<TUser>(userId.ToString(), cancellationToken);
        }

        /// <summary>
        /// Find user login by given parameters.
        /// </summary>
        /// <param name="userId">Id of the user.</param>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Provider key.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(
            TKey userId,
            string loginProvider,
            string providerKey,
            CancellationToken cancellationToken)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            var user = await DocumentSession.LoadAsync<TUser>(userId.ToString(), cancellationToken);
            if (user != null)
            {
                return (TUserLogin)user.GetUserLogin(loginProvider, providerKey)!;
            }

            return null!;
        }

        /// <summary>
        /// Find user login that matches the given parameters.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Provider key.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(
            string loginProvider,
            string providerKey,
            CancellationToken cancellationToken)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            CompareExchangeValue<string>? reservationValue = await DocumentSession.GetReservationAsync<string>(
                RavenDbCompareExchangeExtension.ReservationType.Login,
                GetLoginReservationUniqueValue(loginProvider, providerKey)
            ).ConfigureAwait(false);

            if (reservationValue is null)
            {
                return null!;
            }

            string userId = reservationValue.Value;

            var user = await DocumentSession.LoadAsync<TUser>(userId, cancellationToken).ConfigureAwait(false);

            IdentityUserLogin<TKey>? userLogin = user?.GetUserLogin(loginProvider, providerKey);
            return (TUserLogin)userLogin!;
        }

        /// <inheritdoc/>
        protected override Task<TRole> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession.Query<TRole>()
                .SingleOrDefaultAsync(role => role.NormalizedName == normalizedRoleName, cancellationToken);
        }

        /// <inheritdoc/>
        protected override Task<TUserRole> FindUserRoleAsync(
            TKey userId,
            TKey roleId,
            CancellationToken cancellationToken)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (roleId == null)
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession.Query<TUser>()
                .Where(user =>
                    user.Id.Equals(userId)
                    && user.Roles.Any(rId => rId.Equals(roleId)))
                .Select(user => new TUserRole()
                {
                    UserId = user.Id,
                    RoleId = roleId,
                })
                .FirstOrDefaultAsync(cancellationToken);
        }

        /// <summary>
        /// If there is a property change that requires uniqueness check, make a new compare exchange
        /// reservation or throw if unique value already exists.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="changeType">Unique property change type.</param>
        /// <returns>Optional property change data if there was a property change and
        /// a successful new compare exchange reservation made.</returns>
        /// <exception cref="UniqueValueExistsException">If new unique value already exists.</exception>
        protected virtual Task<PropertyChange<string>?> ReserveIfUserPropertyChangedAsync(
            TUser user,
            UniqueUserPropertyChangeType changeType)
        {
            RavenDbCompareExchangeExtension.ReservationType cmpExchangeReservationType;
            string changedPropertyName;
            string newUniqueValue;

            switch (changeType)
            {
                case UniqueUserPropertyChangeType.Username:
                    cmpExchangeReservationType = RavenDbCompareExchangeExtension.ReservationType.Username;
                    changedPropertyName = nameof(user.NormalizedUserName);
                    newUniqueValue = user.NormalizedUserName;
                    break;
                case UniqueUserPropertyChangeType.Email:
                    cmpExchangeReservationType = RavenDbCompareExchangeExtension.ReservationType.Email;
                    changedPropertyName = nameof(user.NormalizedEmail);
                    newUniqueValue = user.NormalizedEmail;
                    break;
                default:
                    throw new Exception($"Unknown unique user property change type {changeType}");
            }

            return DocumentSession.ReserveIfPropertyChangedAsync(
                user.Id.ToString(),
                changedPropertyName,
                newUniqueValue,
                cmpExchangeReservationType
            );
        }

        private static string GetLoginReservationUniqueValue(string loginProvider, string providerKey)
        {
            return $"{loginProvider}/{providerKey}";
        }
    }
}