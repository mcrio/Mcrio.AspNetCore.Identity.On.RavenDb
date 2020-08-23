using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores
{
    /// <summary>
    /// Class that represents the RavenDB implementation for the identity role store.
    /// </summary>
    public sealed class RavenRoleStore : RavenRoleStore<RavenIdentityRole, string, RavenIdentityClaim,
        RavenIdentityUser, RavenIdentityClaim, RavenIdentityUserLogin, RavenIdentityToken>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore"/> class.
        /// </summary>
        /// <param name="identityDocumentSessionProvider">Document session provider.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        public RavenRoleStore(
            IdentityDocumentSessionProvider identityDocumentSessionProvider,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore> logger)
            : base(identityDocumentSessionProvider(), errorDescriber, logger)
        {
            if (identityDocumentSessionProvider == null)
            {
                throw new ArgumentNullException(nameof(identityDocumentSessionProvider));
            }
        }

        /// <inheritdoc/>
        protected override RavenIdentityClaim CreateRoleClaim(Claim claim)
        {
            return new RavenIdentityClaim(claim);
        }
    }

    /// <summary>
    /// Class that represents the RavenDB implementation for the identity role store.
    /// </summary>
    /// <typeparam name="TRole">Role type.</typeparam>
    /// <typeparam name="TKey">Role id type.</typeparam>
    /// <typeparam name="TRoleClaim">Role claim type.</typeparam>
    /// <typeparam name="TUser">User type.</typeparam>
    /// <typeparam name="TUserClaim">User claim type.</typeparam>
    /// <typeparam name="TUserLogin">User login type.</typeparam>
    /// <typeparam name="TUserToken">User token type.</typeparam>
    public abstract class RavenRoleStore<TRole, TKey, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken> :
        IRoleClaimStore<TRole>, IQueryableRoleStore<TRole>
        where TRole : RavenIdentityRole<TKey, TRoleClaim>
        where TKey : IEquatable<TKey>
        where TRoleClaim : RavenIdentityClaim
        where TUser : RavenIdentityUser<TKey, TUserClaim, TUserLogin, TUserToken>
        where TUserClaim : RavenIdentityClaim
        where TUserLogin : RavenIdentityUserLogin
        where TUserToken : RavenIdentityToken
    {
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore{TRole,TKey,TRoleClaim,TUser,TUserClaim,TUserLogin,TUserToken}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        protected RavenRoleStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore<TRole, TKey, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken>> logger)
        {
            DocumentSession = documentSession ?? throw new ArgumentNullException(nameof(documentSession));
            ErrorDescriber = errorDescriber ?? throw new ArgumentNullException(nameof(errorDescriber));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <inheritdoc/>
        public virtual IQueryable<TRole> Roles => DocumentSession.Query<TRole>();

        /// <summary>
        /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
        /// </summary>
        /// <value>
        /// True if changes should be automatically persisted, otherwise false.
        /// </value>
        public virtual bool AutoSaveChanges { get; set; } = true;

        /// <summary>
        /// Gets the document session.
        /// </summary>
        protected virtual IAsyncDocumentSession DocumentSession { get; }

        /// <summary>
        /// Gets the error describer.
        /// </summary>
        protected virtual IdentityErrorDescriber ErrorDescriber { get; }

        /// <summary>
        /// Gets or sets the logger.
        /// </summary>
        protected virtual ILogger<RavenRoleStore<TRole, TKey, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken>>
            Logger { get; }

        /// <inheritdoc/>
        public virtual void Dispose() => _disposed = true;

        /// <inheritdoc/>
        public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (string.IsNullOrWhiteSpace(role.Name))
            {
                throw new ArgumentNullException(nameof(role.Name));
            }

            if (string.IsNullOrWhiteSpace(role.NormalizedName))
            {
                throw new ArgumentNullException(nameof(role.NormalizedName));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            bool nameReservationResult = await DocumentSession.CreateReservationAsync<string>(
                RavenDbCompareExchangeExtension.ReservationType.Role,
                RoleNameCompareExchangeUniqueValueModifier(role, role.NormalizedName)
            ).ConfigureAwait(false);
            if (!nameReservationResult)
            {
                return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name));
            }

            var saveSuccess = false;
            try
            {
                // note: role.Id may be null as base class does not implement non-nullable reference types
                await DocumentSession
                    .StoreAsync(role, string.Empty, role.Id?.ToString(), cancellationToken)
                    .ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                saveSuccess = true;
                return IdentityResult.Success;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name));
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed reserving role name at the compare exchange. {}", ex.Message);
                return IdentityResult.Failed(ErrorDescriber.DefaultError());
            }
            finally
            {
                if (!saveSuccess)
                {
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Role,
                        RoleNameCompareExchangeUniqueValueModifier(role, role.NormalizedName)
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing role name '{role.NormalizedName}' from compare exchange "
                        );
                    }
                }
            }
        }

        /// <inheritdoc/>
        /// We expect the entity to be already loaded into Ravens Unit of work.
        public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (string.IsNullOrWhiteSpace(role.Name))
            {
                throw new ArgumentNullException(nameof(role.Name));
            }

            if (string.IsNullOrWhiteSpace(role.NormalizedName))
            {
                throw new ArgumentNullException(nameof(role.NormalizedName));
            }

            if (!DocumentSession.Advanced.IsLoaded(role.Id.ToString()))
            {
                throw new Exception("Role is expected to be already loaded in the RavenDB session.");
            }

            // check if normalized name has changed, and if yes make sure it's unique by reserving it
            PropertyChange<string>? normalizedNameChange = null;

            var saveSuccess = false;
            try
            {
                normalizedNameChange = await ReserveIfRoleNameChangedAsync(role).ConfigureAwait(false);

                string changeVector = DocumentSession.Advanced.GetChangeVectorFor(role);
                await DocumentSession
                    .StoreAsync(role, changeVector, role.Id.ToString(), cancellationToken)
                    .ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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
                Logger.LogError(ex, "Failed updating role. {}", ex.Message);
                return IdentityResult.Failed(ErrorDescriber.DefaultError());
            }
            finally
            {
                if (normalizedNameChange != null)
                {
                    string reservationToRemove = RoleNameCompareExchangeUniqueValueModifier(
                        role,
                        saveSuccess
                            ? normalizedNameChange.OldPropertyValue
                            : normalizedNameChange.NewPropertyValue
                    );
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Role,
                        reservationToRemove
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing role name '{reservationToRemove}' from compare exchange "
                        );
                    }
                }
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (!DocumentSession.Advanced.IsLoaded(role.Id.ToString()))
            {
                throw new Exception("Role is expected to be already loaded in the RavenDB session.");
            }

            // if there are users assigned to this role do not allow deletion
            int userInRoleCount = await DocumentSession.Query<TUser>()
                .CountAsync(
                    user => user.Roles.Any(roleId => roleId.Equals(role.Id)),
                    cancellationToken
                );
            if (userInRoleCount > 0)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "UsersInRole",
                    Description = "There are users assigned to this role.",
                });
            }

            string? changeVector = DocumentSession.Advanced.GetChangeVectorFor(role);
            var saveSuccess = false;
            try
            {
                DocumentSession.Delete(role.Id.ToString(), changeVector);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                saveSuccess = true;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }
            finally
            {
                if (saveSuccess)
                {
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Role,
                        RoleNameCompareExchangeUniqueValueModifier(role, role.NormalizedName)
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing role name '{role.NormalizedName}' from compare exchange "
                        );
                    }
                }
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public virtual Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id.ToString());
        }

        /// <inheritdoc/>
        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        /// <inheritdoc/>
        public virtual Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public virtual Task<string> GetNormalizedRoleNameAsync(
            TRole role,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.NormalizedName);
        }

        /// <inheritdoc/>
        public virtual Task SetNormalizedRoleNameAsync(
            TRole role,
            string normalizedName,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (string.IsNullOrWhiteSpace(normalizedName))
            {
                throw new ArgumentNullException(nameof(normalizedName));
            }

            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public virtual Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            return DocumentSession.LoadAsync<TRole>(roleId, cancellationToken);
        }

        /// <summary>
        /// Finds a role by given name.
        /// </summary>
        /// <param name="normalizedRoleName">Normalized role name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        /// <exception cref="Exception">When there is more than one result found.</exception>
        public virtual Task<TRole> FindByNameAsync(
            string normalizedRoleName,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            return DocumentSession.Query<TRole>()
                .SingleOrDefaultAsync(role => role.NormalizedName == normalizedRoleName, cancellationToken);
        }

        /// <inheritdoc/>
        public virtual Task<IList<Claim>> GetClaimsAsync(
            TRole role,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult<IList<Claim>>(
                role.Claims.Select(claim => claim.ToClaim()).ToList()
            );
        }

        /// <inheritdoc/>
        public virtual Task AddClaimAsync(
            TRole role,
            Claim claim,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role is null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim is null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            role.AddClaim(CreateRoleClaim(claim));
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        public virtual Task RemoveClaimAsync(
            TRole role,
            Claim claim,
            CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            if (role is null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim is null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            role.RemoveClaim(claim.Type, claim.Value);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Creates a role claim.
        /// </summary>
        /// <param name="claim">Source claim.</param>
        /// <returns>Role claim.</returns>
        protected abstract TRoleClaim CreateRoleClaim(Claim claim);

        /// <summary>
        /// Optionally modify the role name unique value used in the compare exchange.
        /// Can be used if extending service for multi tenant support.
        /// </summary>
        /// <param name="role">Role object.</param>
        /// <param name="uniqueValue">Unique value to modify.</param>
        /// <returns>Final email unique value used in the compare exchange.</returns>
        protected virtual string RoleNameCompareExchangeUniqueValueModifier(TRole role, string uniqueValue)
        {
            return uniqueValue;
        }

        /// <summary>
        /// Throws and <see cref="ObjectDisposedException"/> if object was disposed.
        /// </summary>
        /// <param name="token">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <exception cref="ObjectDisposedException">When object was disposed.</exception>
        protected virtual void ThrowIfCancelledOrDisposed(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
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

        /// <summary>
        /// If there is a property change that requires uniqueness check, make a new compare exchange
        /// reservation or throw if unique value already exists.
        /// </summary>
        /// <param name="role">Role.</param>
        /// <returns>Optional property change data if there was a property change and
        /// a successful new compare exchange reservation made.</returns>
        /// <exception cref="UniqueValueExistsException">If new unique value already exists.</exception>
        protected virtual Task<PropertyChange<string>?> ReserveIfRoleNameChangedAsync(TRole role)
        {
            const RavenDbCompareExchangeExtension.ReservationType cmpExchangeReservationType =
                RavenDbCompareExchangeExtension.ReservationType.Role;
            const string changedPropertyName = nameof(role.NormalizedName);
            string newValue = role.NormalizedName;
            string newCompareExchangeUniqueValue = RoleNameCompareExchangeUniqueValueModifier(
                role,
                role.NormalizedName
            );

            return DocumentSession.ReserveIfPropertyChangedAsync(
                role.Id.ToString(),
                changedPropertyName,
                newValue,
                newCompareExchangeUniqueValue,
                cmpExchangeReservationType
            );
        }
    }
}