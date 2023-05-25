using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Claims;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Extensions;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Raven.Client.Documents;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores
{
    /// <inheritdoc />
    public class RavenRoleStore : RavenRoleStore<RavenIdentityRole, RavenIdentityUser>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore"/> class.
        /// </summary>
        /// <param name="documentSessionProvider">Identity Document session provider.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        public RavenRoleStore(
            IdentityDocumentSessionProvider documentSessionProvider,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(documentSessionProvider, errorDescriber, logger, uniqueValuesReservationOptions)
        {
        }
    }

    /// <inheritdoc />
    public class RavenRoleStore<TRole, TUser> : RavenRoleStore<TRole, TUser, UniqueReservation>
        where TRole : RavenIdentityRole
        where TUser : RavenIdentityUser
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore{TRole,TUser}"/> class.
        /// </summary>
        /// <param name="documentSessionProvider">Identity Document session provider.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenRoleStore(
            IdentityDocumentSessionProvider documentSessionProvider,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore<TRole, TUser>> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(documentSessionProvider, errorDescriber, logger, uniqueValuesReservationOptions)
        {
        }

        /// <inheritdoc />
        protected override UniqueReservationDocumentUtility<UniqueReservation> CreateUniqueReservationDocumentsUtility(
            UniqueReservationType reservationType,
            string uniqueValue)
        {
            Debug.Assert(
                UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues,
                "Expected reservation documents to be configured to use unique value reservation documents."
            );
            return new UniqueReservationDocumentUtility(
                DocumentSession,
                reservationType,
                uniqueValue
            );
        }
    }

    /// <inheritdoc />
    public abstract class RavenRoleStore<TRole, TUser, TUniqueReservation> : RavenRoleStore<TRole, RavenIdentityClaim,
        TUser, RavenIdentityClaim, RavenIdentityUserLogin, RavenIdentityToken, TUniqueReservation>
        where TRole : RavenIdentityRole
        where TUser : RavenIdentityUser
        where TUniqueReservation : UniqueReservation
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore{TRole,TUser,TUniqueReservation}"/> class.
        /// </summary>
        /// <param name="documentSessionProvider">Identity Document session provider.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenRoleStore(
            IdentityDocumentSessionProvider documentSessionProvider,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore<TRole, TUser, TUniqueReservation>> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(documentSessionProvider(), errorDescriber, logger, uniqueValuesReservationOptions)
        {
            if (documentSessionProvider == null)
            {
                throw new ArgumentNullException(nameof(documentSessionProvider));
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
    /// <typeparam name="TRoleClaim">Role claim type.</typeparam>
    /// <typeparam name="TUser">User type.</typeparam>
    /// <typeparam name="TUserClaim">User claim type.</typeparam>
    /// <typeparam name="TUserLogin">User login type.</typeparam>
    /// <typeparam name="TUserToken">User token type.</typeparam>
    /// <typeparam name="TUniqueReservation">Unique values reservation document type.</typeparam>
    public abstract class RavenRoleStore<TRole, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken,
        TUniqueReservation> :
        IRoleClaimStore<TRole>, IQueryableRoleStore<TRole>
        where TRole : RavenIdentityRole<TRoleClaim>
        where TRoleClaim : RavenIdentityClaim
        where TUser : RavenIdentityUser<TUserClaim, TUserLogin, TUserToken>
        where TUserClaim : RavenIdentityClaim
        where TUserLogin : RavenIdentityUserLogin
        where TUserToken : RavenIdentityToken
        where TUniqueReservation : UniqueReservation
    {
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenRoleStore{TRole,TRoleClaim,TUser,TUserClaim,TUserLogin,TUserToken,TUniqueReservation}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="errorDescriber">Error describer.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenRoleStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber errorDescriber,
            ILogger<RavenRoleStore<TRole, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken, TUniqueReservation>>
                logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
        {
            DocumentSession = documentSession ?? throw new ArgumentNullException(nameof(documentSession));
            ErrorDescriber = errorDescriber ?? throw new ArgumentNullException(nameof(errorDescriber));
            Logger = logger ?? throw new ArgumentNullException(nameof(logger));
            UniqueValuesReservationOptions = uniqueValuesReservationOptions ??
                                             throw new ArgumentNullException(nameof(uniqueValuesReservationOptions));
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
        protected virtual ILogger<RavenRoleStore<TRole, TRoleClaim, TUser, TUserClaim, TUserLogin, TUserToken,
                TUniqueReservation>>
            Logger { get; }

        /// <summary>
        /// Gets the unique value representation options.
        /// </summary>
        protected UniqueValuesReservationOptions UniqueValuesReservationOptions { get; }

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

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            // for unique value reservations
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            // no change vector as we rely on cluster wide optimistic concurrency and atomic guards
            await DocumentSession
                .StoreAsync(role, cancellationToken)
                .ConfigureAwait(false);

            // handle unique reservation
            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Role,
                        role.NormalizedName
                    );
                bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                if (uniqueExists)
                {
                    return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name));
                }

                await uniqueReservationUtil
                    .CreateReservationDocumentAddToUnitOfWorkAsync(role.Id)
                    .ConfigureAwait(false);
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                string compareExchangeKey = compareExchangeUtility.CreateCompareExchangeKey(
                    UniqueReservationType.Role,
                    role.NormalizedName
                );
                CompareExchangeValue<string>? existingCompareExchange = await DocumentSession
                    .Advanced
                    .ClusterTransaction
                    .GetCompareExchangeValueAsync<string>(compareExchangeKey, cancellationToken)
                    .ConfigureAwait(false);

                if (existingCompareExchange != null)
                {
                    return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name));
                }

                DocumentSession
                    .Advanced
                    .ClusterTransaction
                    .CreateCompareExchangeValue(
                        compareExchangeKey,
                        role.Id
                    );
            }

            try
            {
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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

            if (!DocumentSession.Advanced.IsLoaded(role.Id))
            {
                throw new Exception("Role expected to be loaded in RavenDb unit of work prior to update");
            }

            if (string.IsNullOrWhiteSpace(role.Name))
            {
                throw new ArgumentNullException(nameof(role.Name));
            }

            if (string.IsNullOrWhiteSpace(role.NormalizedName))
            {
                throw new ArgumentNullException(nameof(role.NormalizedName));
            }

            if (!DocumentSession.Advanced.IsLoaded(role.Id))
            {
                throw new Exception("Role is expected to be already loaded in the RavenDB session.");
            }

            // check if normalized name has changed, and if yes make sure it's unique by reserving it
            if (DocumentSession.IfPropertyChanged(
                    role,
                    changedPropertyName: nameof(role.NormalizedName),
                    newPropertyValue: role.NormalizedName,
                    out PropertyChange<string?>? propertyChange
                ))
            {
                Debug.Assert(propertyChange != null, $"Unexpected NULL value for {nameof(propertyChange)}");

                Debug.Assert(
                    !string.IsNullOrWhiteSpace(propertyChange.OldPropertyValue),
                    "Role name must never be empty or NULL."
                );

                // cluster wide as we will deal with compare exchange values either directly or as atomic guards
                DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
                DocumentSession.Advanced.UseOptimisticConcurrency =
                    false; // cluster wide tx doesn't support opt. concurrency

                if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
                {
                    UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Role,
                            role.NormalizedName
                        );
                    bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                    if (uniqueExists)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateRoleName(role.Name));
                    }

                    await uniqueReservationUtil.UpdateReservationAndAddToUnitOfWork(
                        oldUniqueValue: propertyChange.OldPropertyValue,
                        ownerDocumentId: role.Id
                    ).ConfigureAwait(false);
                }
                else
                {
                    CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                    IdentityError? reservationUpdateError = await compareExchangeUtility
                        .PrepareReservationUpdateInUnitOfWorkAsync(
                            UniqueReservationType.Role,
                            role.NormalizedName,
                            propertyChange.OldPropertyValue,
                            role.Id,
                            ErrorDescriber,
                            Logger,
                            cancellationToken
                        ).ConfigureAwait(false);
                    if (reservationUpdateError != null)
                    {
                        return IdentityResult.Failed(reservationUpdateError);
                    }
                }
            }

            try
            {
                // in cluster wide mode relying on optimistic concurrency using atomic guards
                if (((AsyncDocumentSession)DocumentSession).TransactionMode != TransactionMode.ClusterWide)
                {
                    string changeVector = DocumentSession.Advanced.GetChangeVectorFor(role);
                    await DocumentSession
                        .StoreAsync(role, changeVector, role.Id, cancellationToken)
                        .ConfigureAwait(false);
                }

                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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

            if (!DocumentSession.Advanced.IsLoaded(role.Id))
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
                return IdentityResult.Failed(
                    new IdentityError
                    {
                        Code = "UsersInRole",
                        Description = "There are users assigned to this role.",
                    });
            }

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Role,
                        role.NormalizedName
                    );
                await uniqueReservationUtil.MarkReservationForDeletionAsync().ConfigureAwait(false);
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                await compareExchangeUtility.PrepareReservationForRemovalAsync(
                    UniqueReservationType.Role,
                    role.NormalizedName,
                    Logger,
                    cancellationToken
                ).ConfigureAwait(false);
            }

            try
            {
                DocumentSession.Delete(role.Id);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
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

            return Task.FromResult(role.Id);
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
        /// Compare exchange utility factory.
        /// </summary>
        /// <returns>An instance of <see cref="CompareExchangeUtility"/>.</returns>
        protected virtual CompareExchangeUtility CreateCompareExchangeUtility()
        {
            Debug.Assert(
                !UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues,
                "Expected compare exchange values to be configured for unique value reservations."
            );
            return new CompareExchangeUtility(DocumentSession);
        }

        /// <summary>
        /// Create an instance of <see cref="UniqueReservationDocumentUtility"/>.
        /// </summary>
        /// <param name="reservationType"></param>
        /// <param name="uniqueValue"></param>
        /// <returns>Instance of <see cref="UniqueReservationDocumentUtility"/>.</returns>
        protected abstract UniqueReservationDocumentUtility<TUniqueReservation> CreateUniqueReservationDocumentsUtility(
            UniqueReservationType reservationType,
            string uniqueValue);
    }
}