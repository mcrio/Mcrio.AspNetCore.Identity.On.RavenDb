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
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;

namespace Mcrio.AspNetCore.Identity.RavenDb
{
    /// <summary>
    /// Class that represents the RavenDB implementation for the identity role store.
    /// </summary>
    public class RavenRoleStore : RavenRoleStore<RavenIdentityRole, string, RavenIdentityUser>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="logger">Logger.</param>
        public RavenRoleStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            ILogger<RavenRoleStore> logger)
            : base(documentSession, describer, logger)
        {
        }
    }

    /// <summary>
    /// Class that represents the RavenDB implementation for the identity role store.
    /// </summary>
    /// <typeparam name="TRole">Role type.</typeparam>
    /// <typeparam name="TKey">Role id type.</typeparam>
    /// <typeparam name="TUser">User type.</typeparam>
    public class RavenRoleStore<TRole, TKey, TUser> :
        IRoleClaimStore<TRole>, IQueryableRoleStore<TRole>
        where TRole : RavenIdentityRole<TKey>
        where TUser : RavenIdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        protected readonly IAsyncDocumentSession DocumentSession;
        protected readonly IdentityErrorDescriber Describer;
        protected readonly ILogger<RavenRoleStore<TRole, TKey, TUser>> Logger;
        protected bool Disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore{TRole,TKey,TRoleClaim}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="logger">Logger.</param>
        public RavenRoleStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            ILogger<RavenRoleStore<TRole, TKey, TUser>> logger)
        {
            DocumentSession = documentSession ?? throw new ArgumentNullException(nameof(documentSession));
            Describer = describer ?? throw new ArgumentNullException(nameof(describer));
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

        /// <inheritdoc/>
        public virtual void Dispose() => Disposed = true;

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

            string nameUniqueValue = role.NormalizedName;

            bool nameReservationResult = await DocumentSession.CreateReservationAsync<string>(
                RavenDbCompareExchangeExtension.ReservationType.Role,
                nameUniqueValue
            ).ConfigureAwait(false);

            if (!nameReservationResult)
            {
                return IdentityResult.Failed(Describer.ConcurrencyFailure());
            }

            var saveSuccess = false;
            try
            {
                await DocumentSession
                    .StoreAsync(role, string.Empty, role.Id.ToString(), cancellationToken)
                    .ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
                saveSuccess = true;
                return IdentityResult.Success;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(Describer.DuplicateRoleName(role.Name));
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed reserving role name at the compare exchange. {}", ex.Message);
                return IdentityResult.Failed(Describer.DefaultError());
            }
            finally
            {
                if (!saveSuccess)
                {
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Role,
                        nameUniqueValue
                    ).ConfigureAwait(false);
                    if (!removeResult)
                    {
                        Logger.LogError(
                            $"Failed removing role name '{nameUniqueValue}' from compare exchange "
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
                normalizedNameChange = await ReserveIfRoleNameChangedAsync(
                    role
                ).ConfigureAwait(false);

                string changeVector = DocumentSession.Advanced.GetChangeVectorFor(role);
                await DocumentSession.StoreAsync(role, changeVector, role.Id.ToString(), cancellationToken);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
            }
            catch (UniqueValueExistsException ex)
            {
                Logger.LogInformation(ex, $"Failed reserving unique value: {ex.Message}");
                return IdentityResult.Failed(Describer.ConcurrencyFailure());
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(Describer.ConcurrencyFailure());
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed updating role. {}", ex.Message);
                return IdentityResult.Failed(Describer.DefaultError());
            }
            finally
            {
                if (normalizedNameChange != null)
                {
                    var reservationToRemove = saveSuccess
                        ? normalizedNameChange.OldValue
                        : normalizedNameChange.NewValue;
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

            var changeVector = DocumentSession.Advanced.GetChangeVectorFor(role);

            var saveSuccess = false;
            try
            {
                DocumentSession.Delete(role.Id.ToString(), changeVector);
                await SaveChangesAsync(cancellationToken);
                saveSuccess = true;
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(Describer.ConcurrencyFailure());
            }
            finally
            {
                if (saveSuccess)
                {
                    bool removeResult = await DocumentSession.RemoveReservationAsync(
                        RavenDbCompareExchangeExtension.ReservationType.Role,
                        role.NormalizedName
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

            role.AddClaim(claim);
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

            role.RemoveClaim(claim);
            return Task.CompletedTask;
        }

        /// <summary>
        /// Throws and <see cref="ObjectDisposedException"/> if object was disposed.
        /// </summary>
        /// <param name="token">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <exception cref="ObjectDisposedException">When object was disposed.</exception>
        protected virtual void ThrowIfCancelledOrDisposed(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (Disposed)
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
            string newUniqueValue = role.NormalizedName;

            return DocumentSession.ReserveIfPropertyChangedAsync(
                role.Id.ToString(),
                changedPropertyName,
                newUniqueValue,
                cmpExchangeReservationType
            );
        }
    }
}