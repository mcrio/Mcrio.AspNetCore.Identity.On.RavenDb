using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
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
using Microsoft.Extensions.Options;
using Raven.Client.Documents;
using Raven.Client.Documents.Commands;
using Raven.Client.Documents.Linq;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores
{
    /// <inheritdoc />
    public class RavenUserStore : RavenUserStore<RavenIdentityUser, RavenIdentityRole>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore"/> class.
        /// </summary>
        /// <param name="identityDocumentSessionProvider">Identity document session provider.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        public RavenUserStore(
            IdentityDocumentSessionProvider identityDocumentSessionProvider,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(identityDocumentSessionProvider, describer, optionsAccessor, logger, uniqueValuesReservationOptions)
        {
        }
    }

    /// <inheritdoc />
    public class RavenUserStore<TUser, TRole> : RavenUserStore<TUser, TRole, UniqueReservation>
        where TUser : RavenIdentityUser
        where TRole : RavenIdentityRole
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser,TRole}"/> class.
        /// </summary>
        /// <param name="identityDocumentSessionProvider">Identity document session provider.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        public RavenUserStore(
            IdentityDocumentSessionProvider identityDocumentSessionProvider,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TRole>> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(
                identityDocumentSessionProvider,
                describer,
                optionsAccessor,
                logger,
                uniqueValuesReservationOptions)
        {
        }

        /// <inheritdoc />
        protected override UniqueReservationDocumentUtility<UniqueReservation> CreateUniqueReservationDocumentsUtility(
            UniqueReservationType reservationType,
            string uniqueValue)
        {
            Debug.Assert(
                UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues,
                "Expected reservation documents to be configured for unique value reservations."
            );
            return new UniqueReservationDocumentUtility(
                DocumentSession,
                reservationType,
                uniqueValue
            );
        }
    }

    /// <inheritdoc />
    public abstract class RavenUserStore<TUser, TRole, TUniqueReservation> : RavenUserStore<TUser, RavenIdentityClaim,
        RavenIdentityToken, RavenIdentityUserLogin, TRole, RavenIdentityClaim, TUniqueReservation>
        where TUser : RavenIdentityUser
        where TRole : RavenIdentityRole
        where TUniqueReservation : UniqueReservation
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser,TRole,TUniqueReservation}"/> class.
        /// </summary>
        /// <param name="identityDocumentSessionProvider">Identity document session provider.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenUserStore(
            IdentityDocumentSessionProvider identityDocumentSessionProvider,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TRole, TUniqueReservation>> logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(
                identityDocumentSessionProvider(),
                describer,
                optionsAccessor,
                logger,
                uniqueValuesReservationOptions)
        {
        }

        /// <inheritdoc />
        protected override RavenIdentityClaim CreateUserClaim(Claim claim)
        {
            return new RavenIdentityClaim(claim);
        }

        /// <inheritdoc />
        protected override RavenIdentityToken CreateUserToken(string loginProvider, string tokenName, string tokenValue)
        {
            return new RavenIdentityToken(
                loginProvider,
                tokenName,
                tokenValue
            );
        }

        /// <inheritdoc />
        protected override RavenIdentityUserLogin CreateUserLogin(UserLoginInfo loginInfo)
        {
            return new RavenIdentityUserLogin(
                loginInfo.LoginProvider,
                loginInfo.ProviderKey,
                loginInfo.ProviderDisplayName
            );
        }
    }

    /// <inheritdoc />
    public abstract class RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim,
        TUniqueReservation>
        : RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim, IdentityUserClaim<string>,
            IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>,
            IdentityRoleClaim<string>, TUniqueReservation>
        where TUser : RavenIdentityUser<TUserClaim, TUserLogin, TUserToken>
        where TRole : RavenIdentityRole<TRoleClaim>
        where TUserClaim : RavenIdentityClaim
        where TRoleClaim : RavenIdentityClaim
        where TUserToken : RavenIdentityToken
        where TUserLogin : RavenIdentityUserLogin
        where TUniqueReservation : UniqueReservation
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser,TUserClaim,TUserToken,TUserLogin,TRole,TRoleClaim,TUniqueReservation}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenUserStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim, TUniqueReservation>>
                logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(documentSession, describer, optionsAccessor, logger, uniqueValuesReservationOptions)
        {
        }
    }

    /// <inheritdoc />
    public abstract class RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim,
        TAspUserClaim, TAspUserRole, TAspUserLogin, TAspUserToken, TAspRoleClaim, TUniqueReservation> :
        UserStoreBase<TUser, TRole, string, TAspUserClaim, TAspUserRole, TAspUserLogin,
            TAspUserToken, TAspRoleClaim>
        where TUser : RavenIdentityUser<TUserClaim, TUserLogin, TUserToken>
        where TRole : RavenIdentityRole<TRoleClaim>
        where TRoleClaim : RavenIdentityClaim
        where TUserClaim : RavenIdentityClaim
        where TUserToken : RavenIdentityToken
        where TUserLogin : RavenIdentityUserLogin
        where TAspUserClaim : IdentityUserClaim<string>, new()
        where TAspUserRole : IdentityUserRole<string>, new()
        where TAspUserLogin : IdentityUserLogin<string>, new()
        where TAspUserToken : IdentityUserToken<string>, new()
        where TAspRoleClaim : IdentityRoleClaim<string>, new()
        where TUniqueReservation : UniqueReservation
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenUserStore{TUser,TUserClaim,TUserToken,TUserLogin,TRole,TRoleClaim,TAspUserClaim,TAspUserRole,TAspUserLogin,TAspUserToken,TAspRoleClaim,TUniqueReservation}"/> class.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="describer">Error describer.</param>
        /// <param name="optionsAccessor">Identity options accessor.</param>
        /// <param name="logger">Logger.</param>
        /// <param name="uniqueValuesReservationOptions">Unique values reservation options.</param>
        protected RavenUserStore(
            IAsyncDocumentSession documentSession,
            IdentityErrorDescriber describer,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim, TAspUserClaim,
                    TAspUserRole, TAspUserLogin, TAspUserToken, TAspRoleClaim, TUniqueReservation>>
                logger,
            UniqueValuesReservationOptions uniqueValuesReservationOptions)
            : base(describer)
        {
            DocumentSession = documentSession ?? throw new ArgumentNullException(nameof(documentSession));
            OptionsAccessor = optionsAccessor;
            Logger = logger;
            UniqueValuesReservationOptions = uniqueValuesReservationOptions;
        }

        /// <inheritdoc/>
        public override IQueryable<TUser> Users => DocumentSession.Query<TUser>();

        /// <summary>
        /// Indicates if changes should be persisted to DB
        /// after CreateAsync, UpdateAsync, DeleteAsync, AddLoginAsync, RemoveLoginAsync method are called.
        /// </summary>
        /// <value>
        /// TRUE if changes should be persisted after CreateAsync, UpdateAsync, DeleteAsync,
        /// AddLoginAsync or RemoveLoginAsync, FALSE otherwise.
        /// </value>
        public virtual bool AutoSaveChanges { get; set; } = true;

        /// <summary>
        /// RavenDB document session.
        /// </summary>
        protected IAsyncDocumentSession DocumentSession { get; }

        /// <summary>
        /// Identity options accessor.
        /// </summary>
        protected IOptions<IdentityOptions> OptionsAccessor { get; }

        /// <summary>
        /// Logger.
        /// </summary>
        protected ILogger<RavenUserStore<TUser, TUserClaim, TUserToken, TUserLogin, TRole, TRoleClaim,
            TAspUserClaim,
            TAspUserRole, TAspUserLogin, TAspUserToken, TAspRoleClaim, TUniqueReservation>> Logger { get; }

        /// <summary>
        /// Gets the unique value representation options.
        /// </summary>
        protected UniqueValuesReservationOptions UniqueValuesReservationOptions { get; }

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

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            // for unique value reservations
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            // no change vector as we rely on cluster wide optimistic concurrency and atomic guards
            await DocumentSession
                .StoreAsync(user, cancellationToken)
                .ConfigureAwait(false);

            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                // reserve username
                {
                    UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Username,
                            user.NormalizedUserName
                        );
                    bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                    if (uniqueExists)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateUserName(user.UserName));
                    }

                    await uniqueReservationUtil
                        .CreateReservationDocumentAddToUnitOfWorkAsync(user.Id)
                        .ConfigureAwait(false);
                }

                // reserve email if required
                if (OptionsAccessor.Value.User.RequireUniqueEmail)
                {
                    if (string.IsNullOrWhiteSpace(user.NormalizedEmail))
                    {
                        throw new ArgumentNullException(nameof(user.NormalizedEmail));
                    }

                    UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Email,
                            user.NormalizedEmail
                        );
                    bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                    if (uniqueExists)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateEmail(user.Email));
                    }

                    await uniqueReservationUtil
                        .CreateReservationDocumentAddToUnitOfWorkAsync(user.Id)
                        .ConfigureAwait(false);
                }
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                {
                    // reserve username
                    string usernameCompareExchangeKey = compareExchangeUtility.CreateCompareExchangeKey(
                        UniqueReservationType.Username,
                        user.NormalizedUserName
                    );
                    CompareExchangeValue<string>? existingUsernameCompareExchange = await DocumentSession
                        .Advanced
                        .ClusterTransaction
                        .GetCompareExchangeValueAsync<string>(usernameCompareExchangeKey, cancellationToken)
                        .ConfigureAwait(false);

                    if (existingUsernameCompareExchange != null)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateUserName(user.UserName));
                    }

                    DocumentSession
                        .Advanced
                        .ClusterTransaction
                        .CreateCompareExchangeValue(
                            usernameCompareExchangeKey,
                            user.Id
                        );
                }

                // reserve email if unique email required
                if (OptionsAccessor.Value.User.RequireUniqueEmail)
                {
                    if (string.IsNullOrWhiteSpace(user.NormalizedEmail))
                    {
                        throw new ArgumentNullException(nameof(user.NormalizedEmail));
                    }

                    string emailCompareExchangeKey = compareExchangeUtility.CreateCompareExchangeKey(
                        UniqueReservationType.Email,
                        user.NormalizedEmail
                    );

                    CompareExchangeValue<string>? existingEmailCompareExchange = await DocumentSession
                        .Advanced
                        .ClusterTransaction
                        .GetCompareExchangeValueAsync<string>(emailCompareExchangeKey, cancellationToken)
                        .ConfigureAwait(false);

                    if (existingEmailCompareExchange != null)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateEmail(user.Email));
                    }

                    DocumentSession
                        .Advanced
                        .ClusterTransaction
                        .CreateCompareExchangeValue(
                            emailCompareExchangeKey,
                            user.Id
                        );
                }
            }

            try
            {
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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

            if (!DocumentSession.Advanced.IsLoaded(user.Id))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            // if username has changed make sure it's unique by reserving it
            if (DocumentSession.IfPropertyChanged(
                    user,
                    changedPropertyName: nameof(user.NormalizedUserName),
                    newPropertyValue: user.NormalizedUserName,
                    out PropertyChange<string?>? usernamePropertyChange
                ))
            {
                Debug.Assert(
                    usernamePropertyChange != null,
                    $"Unexpected NULL value for {nameof(usernamePropertyChange)}"
                );

                Debug.Assert(
                    !string.IsNullOrWhiteSpace(usernamePropertyChange.OldPropertyValue),
                    "Username must never be empty or NULL."
                );

                // cluster wide as we will deal with compare exchange values either directly or as atomic guards
                DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
                DocumentSession.Advanced.UseOptimisticConcurrency =
                    false; // cluster wide tx doesn't support opt. concurrency

                if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
                {
                    UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Username,
                            user.NormalizedUserName
                        );
                    bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                    if (uniqueExists)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateUserName(user.UserName));
                    }

                    await uniqueReservationUtil.UpdateReservationAndAddToUnitOfWork(
                        usernamePropertyChange.OldPropertyValue,
                        user.Id
                    ).ConfigureAwait(false);
                }
                else
                {
                    CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();

                    IdentityError? reservationUpdateError = await compareExchangeUtility
                        .PrepareReservationUpdateInUnitOfWorkAsync(
                            uniqueReservationType: UniqueReservationType.Username,
                            newUniqueValueNormalized: user.NormalizedUserName,
                            oldUniqueValueNormalized: usernamePropertyChange.OldPropertyValue,
                            compareExchangeValue: user.Id,
                            errorDescriber: ErrorDescriber,
                            logger: Logger,
                            cancellationToken: cancellationToken
                        ).ConfigureAwait(false);
                    if (reservationUpdateError != null)
                    {
                        return IdentityResult.Failed(reservationUpdateError);
                    }
                }
            }

            // if email has changed and if we require unique emails
            if (DocumentSession.IfPropertyChanged(
                    user,
                    changedPropertyName: nameof(user.NormalizedEmail),
                    newPropertyValue: user.NormalizedEmail,
                    out PropertyChange<string?>? emailPropertyChange
                )
                && OptionsAccessor.Value.User.RequireUniqueEmail)
            {
                Debug.Assert(emailPropertyChange != null, $"Unexpected NULL value for {nameof(emailPropertyChange)}");

                // cluster wide as we will deal with compare exchange values either directly or as atomic guards
                DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
                DocumentSession.Advanced.UseOptimisticConcurrency =
                    false; // cluster wide tx doesn't support opt. concurrency

                if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
                {
                    UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Email,
                            user.NormalizedEmail
                        );
                    bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                    if (uniqueExists)
                    {
                        return IdentityResult.Failed(ErrorDescriber.DuplicateEmail(user.Email));
                    }

                    await uniqueReservationUtil
                        .UpdateReservationAndAddToUnitOfWork(
                            emailPropertyChange.OldPropertyValue,
                            user.Id
                        )
                        .ConfigureAwait(false);
                }
                else
                {
                    CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();

                    IdentityError? reservationUpdateError = await compareExchangeUtility
                        .PrepareReservationUpdateInUnitOfWorkAsync(
                            uniqueReservationType: UniqueReservationType.Email,
                            newUniqueValueNormalized: user.NormalizedEmail,
                            oldUniqueValueNormalized: emailPropertyChange.OldPropertyValue,
                            compareExchangeValue: user.Id,
                            errorDescriber: ErrorDescriber,
                            logger: Logger,
                            cancellationToken: cancellationToken
                        ).ConfigureAwait(false);
                    if (reservationUpdateError != null)
                    {
                        return IdentityResult.Failed(reservationUpdateError);
                    }
                }
            }

            // in cluster wide mode relying on atomic guards for optimistic concurrency
            if (((AsyncDocumentSession)DocumentSession).TransactionMode != TransactionMode.ClusterWide)
            {
                string changeVector = DocumentSession.Advanced.GetChangeVectorFor(user);
                await DocumentSession
                    .StoreAsync(user, changeVector, user.Id, cancellationToken)
                    .ConfigureAwait(false);
            }

            try
            {
                await DocumentSession.StoreAsync(user, cancellationToken).ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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

            if (!DocumentSession.Advanced.IsLoaded(user.Id))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> usernameReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Username,
                        user.NormalizedUserName
                    );
                await usernameReservationUtil.MarkReservationForDeletionAsync().ConfigureAwait(false);

                if (OptionsAccessor.Value.User.RequireUniqueEmail)
                {
                    UniqueReservationDocumentUtility<TUniqueReservation> emailReservationUtil =
                        CreateUniqueReservationDocumentsUtility(
                            UniqueReservationType.Email,
                            user.NormalizedEmail
                        );
                    await emailReservationUtil.MarkReservationForDeletionAsync().ConfigureAwait(false);
                }
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();

                await compareExchangeUtility.PrepareReservationForRemovalAsync(
                    UniqueReservationType.Username,
                    user.NormalizedUserName,
                    Logger,
                    cancellationToken
                ).ConfigureAwait(false);

                if (OptionsAccessor.Value.User.RequireUniqueEmail)
                {
                    await compareExchangeUtility.PrepareReservationForRemovalAsync(
                        UniqueReservationType.Email,
                        user.NormalizedEmail!,
                        Logger,
                        cancellationToken
                    ).ConfigureAwait(false);
                }
            }

            try
            {
                DocumentSession.Delete(user.Id);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
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

            return IdentityResult.Success;
        }

        /// <inheritdoc/>
        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);
            return DocumentSession.LoadAsync<TUser>(userId, cancellationToken);
        }

        /// <summary>
        /// Get all users.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns><see cref="Task"/> representing an asynchronous operation.</returns>
        public async IAsyncEnumerable<TUser> GetAllUsersAsync(
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            IRavenQueryable<TUser>? query = DocumentSession.Query<TUser>();
            await using IAsyncEnumerator<StreamResult<TUser>>? streamResult = await DocumentSession
                .Advanced
                .StreamAsync(query, cancellationToken)
                .ConfigureAwait(false);

            while (await streamResult.MoveNextAsync().ConfigureAwait(false))
            {
                yield return streamResult.Current.Document;
            }
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

            return Queryable.Where(
                    DocumentSession
                        .Query<TUser>(), user => user.NormalizedUserName == normalizedUserName
                )
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
                user.AddClaim(CreateUserClaim(claim));
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

            user.ReplaceClaim(CreateUserClaim(claim), CreateUserClaim(newClaim));

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
                user.RemoveClaim(claim.Type, claim.Value);
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

            IQueryable<TUser> query = Queryable.Where(
                DocumentSession.Query<TUser>(),
                user => user.Claims.Any(item => item.Type == claim.Type && item.Value == claim.Value)
            );

            IAsyncEnumerator<StreamResult<TUser>> streamResult = await DocumentSession
                .Advanced
                .StreamAsync(query, cancellationToken)
                .ConfigureAwait(false);

            var users = new List<TUser>();
            while (await streamResult.MoveNextAsync().ConfigureAwait(false))
            {
                users.Add(streamResult.Current.Document);
            }

            return users;
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

            TUserLogin userLogin = CreateUserLogin(login);
            if (user.HasLogin(userLogin))
            {
                return;
            }

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Login,
                        CreateLoginReservationUniqueValue(userLogin.LoginProvider, userLogin.ProviderKey)
                    );
                bool uniqueExists = await uniqueReservationUtil.CheckIfUniqueIsTakenAsync().ConfigureAwait(false);
                if (uniqueExists)
                {
                    return;
                }

                await uniqueReservationUtil
                    .CreateReservationDocumentAddToUnitOfWorkAsync(user.Id)
                    .ConfigureAwait(false);
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                string loginCompareExchangeKey = compareExchangeUtility.CreateCompareExchangeKey(
                    UniqueReservationType.Login,
                    CreateLoginReservationUniqueValue(userLogin.LoginProvider, userLogin.ProviderKey)
                );
                CompareExchangeValue<string>? existingLoginCompareExchange = await DocumentSession
                    .Advanced
                    .ClusterTransaction
                    .GetCompareExchangeValueAsync<string>(loginCompareExchangeKey, cancellationToken)
                    .ConfigureAwait(false);

                if (existingLoginCompareExchange != null)
                {
                    return;
                }

                DocumentSession
                    .Advanced
                    .ClusterTransaction
                    .CreateCompareExchangeValue(
                        loginCompareExchangeKey,
                        user.Id
                    );
            }

            user.AddLogin(userLogin);

            try
            {
                await DocumentSession.StoreAsync(user, cancellationToken).ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed adding login for user {}", user.Id);
            }
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

            if (!DocumentSession.Advanced.IsLoaded(user.Id))
            {
                throw new Exception("User is expected to be already loaded in the RavenDB session.");
            }

            TUserLogin? userLogin = user.GetUserLogin(loginProvider, providerKey);
            if (userLogin is null)
            {
                Logger.LogWarning(
                    "Error removing user login as not found in user object. User {UserId} Provider {LoginProvider} Key {ProviderKey}",
                    user.Id,
                    loginProvider,
                    providerKey
                );
                return;
            }

            user.RemoveLogin(userLogin);

            // cluster wide as we will deal with compare exchange values either directly or as atomic guards
            DocumentSession.Advanced.SetTransactionMode(TransactionMode.ClusterWide);
            DocumentSession.Advanced.UseOptimisticConcurrency =
                false; // cluster wide tx doesn't support opt. concurrency

            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Login,
                        CreateLoginReservationUniqueValue(loginProvider, providerKey)
                    );
                await uniqueReservationUtil
                    .MarkReservationForDeletionAsync()
                    .ConfigureAwait(false);
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                await compareExchangeUtility.PrepareReservationForRemovalAsync(
                    UniqueReservationType.Login,
                    CreateLoginReservationUniqueValue(loginProvider, providerKey),
                    Logger,
                    cancellationToken
                ).ConfigureAwait(false);
            }

            try
            {
                await DocumentSession.StoreAsync(user, cancellationToken).ConfigureAwait(false);
                await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ConcurrencyException)
            {
                Logger.LogInformation(
                    "Failed removing login {LoginProvider} for user {UserName} due do concurrency problem",
                    loginProvider,
                    user.UserName
                );
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

            return Task.FromResult<IList<UserLoginInfo>>(
                user.Logins.Select(
                    login => new UserLoginInfo(
                        login.LoginProvider,
                        login.ProviderKey,
                        login.ProviderDisplayName
                    )).ToList()
            );
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

            return Queryable.Where(
                    DocumentSession
                        .Query<TUser>(), user => user.NormalizedEmail == normalizedEmail
                )
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

            TRole? role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);
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

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);

            if (role is null)
            {
                throw new InvalidOperationException($"Unknown role with normalized name {normalizedRoleName}");
            }

            IQueryable<TUser> query =
                Queryable.Where(DocumentSession.Query<TUser>(), item => item.Roles.Contains(role.Id));

            IAsyncEnumerator<StreamResult<TUser>> streamResult = await DocumentSession
                .Advanced
                .StreamAsync(query, cancellationToken)
                .ConfigureAwait(false);

            var users = new List<TUser>();
            while (await streamResult.MoveNextAsync().ConfigureAwait(false))
            {
                users.Add(streamResult.Current.Document);
            }

            return users;
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

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);

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

            TRole role = await FindRoleAsync(normalizedRoleName, cancellationToken).ConfigureAwait(false);

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

            user.AddOrReplaceToken(CreateUserToken(loginProvider, name, value));
            return Task.CompletedTask;
        }

        /// <summary>
        /// Creates a claim object.
        /// </summary>
        /// <param name="claim">Source claim.</param>
        /// <returns>A claim object.</returns>
        protected abstract TUserClaim CreateUserClaim(Claim claim);

        /// <summary>
        /// Creates a token object.
        /// </summary>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="tokenName">Token name.</param>
        /// <param name="tokenValue">Token value.</param>
        /// <returns>An object representing a user token class.</returns>
        protected abstract TUserToken CreateUserToken(string loginProvider, string tokenName, string tokenValue);

        /// <summary>
        /// Creates a user login object.
        /// </summary>
        /// <param name="loginInfo">Login info.</param>
        /// <returns>An object representing the user login class.</returns>
        protected abstract TUserLogin CreateUserLogin(UserLoginInfo loginInfo);

        /// <summary>
        /// Find user token by given parameters.
        /// </summary>
        /// <param name="user">User.</param>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="name">Token name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override Task<TAspUserToken> FindTokenAsync(
            TUser user,
            string loginProvider,
            string name,
            CancellationToken cancellationToken)
        {
            ThrowIfCancelledOrDisposed(cancellationToken);

            TUserToken? userToken = user.GetToken(loginProvider, name);
            if (userToken is null)
            {
                return Task.FromResult<TAspUserToken>(null!);
            }

            return Task.FromResult(
                CreateUserToken(
                    user,
                    userToken.LoginProvider,
                    userToken.Name,
                    userToken.Value
                ));
        }

        /// <summary>
        /// Adds token to the user.
        /// </summary>
        /// <param name="userToken">User token information.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override Task AddUserTokenAsync(TAspUserToken userToken)
        {
            // We implement the functionality in SetTokenAsync directly, returning completed task.
            return Task.CompletedTask;
        }

        /// <summary>
        /// Removes token from the user.
        /// </summary>
        /// <param name="token">User token information.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task RemoveUserTokenAsync(TAspUserToken token)
        {
            TUser user = await DocumentSession.LoadAsync<TUser>(token.UserId);
            user?.RemoveToken(token.LoginProvider, token.Name);
        }

        /// <summary>
        /// Throws if cancellation is requested or the object is disposed.
        /// </summary>
        /// <param name="token"></param>
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
        protected override Task<TUser> FindUserAsync(string userId, CancellationToken cancellationToken)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            ThrowIfCancelledOrDisposed(cancellationToken);

            return DocumentSession.LoadAsync<TUser>(userId, cancellationToken);
        }

        /// <summary>
        /// Find user login by given parameters.
        /// </summary>
        /// <param name="userId">Id of the user.</param>
        /// <param name="loginProvider">Login provider.</param>
        /// <param name="providerKey">Provider key.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        protected override async Task<TAspUserLogin> FindUserLoginAsync(
            string userId,
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

            TUser? user = await DocumentSession.LoadAsync<TUser>(userId, cancellationToken);
            TUserLogin? userLogin = user?.GetUserLogin(loginProvider, providerKey);
            if (userLogin != null)
            {
                return new TAspUserLogin
                {
                    UserId = user!.Id,
                    LoginProvider = userLogin.LoginProvider,
                    ProviderKey = userLogin.ProviderKey,
                    ProviderDisplayName = userLogin.ProviderDisplayName,
                };
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
        protected override async Task<TAspUserLogin> FindUserLoginAsync(
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

            string? userId;
            if (UniqueValuesReservationOptions.UseReservationDocumentsForUniqueValues)
            {
                UniqueReservationDocumentUtility<TUniqueReservation> uniqueReservationUtil =
                    CreateUniqueReservationDocumentsUtility(
                        UniqueReservationType.Login,
                        CreateLoginReservationUniqueValue(loginProvider, providerKey)
                    );
                UniqueReservation? loginReservation = await uniqueReservationUtil
                    .LoadReservationAsync()
                    .ConfigureAwait(false);

                if (loginReservation is null)
                {
                    return null!;
                }

                userId = loginReservation.ReferenceId;
            }
            else
            {
                CompareExchangeUtility compareExchangeUtility = CreateCompareExchangeUtility();
                string loginCompareExchangeKey = compareExchangeUtility.CreateCompareExchangeKey(
                    UniqueReservationType.Login,
                    CreateLoginReservationUniqueValue(loginProvider, providerKey)
                );
                CompareExchangeValue<string>? loginCompareExchange = await DocumentSession.Advanced.DocumentStore
                    .Operations.SendAsync(
                        new GetCompareExchangeValueOperation<string>(loginCompareExchangeKey),
                        token: cancellationToken
                    ).ConfigureAwait(false);

                if (loginCompareExchange is null)
                {
                    return null!;
                }

                userId = loginCompareExchange.Value;
            }

            Debug.Assert(!string.IsNullOrWhiteSpace(userId), "Unexpected empty value for user id.");
            TUser? user = await DocumentSession.LoadAsync<TUser>(userId, cancellationToken).ConfigureAwait(false);

            if (user is null)
            {
                Logger.LogError(
                    "Unknown user for data returned by compare exchange. Provider '{LoginProvider}', user id '{UserId}'",
                    loginProvider,
                    userId
                );
                return null!;
            }

            TUserLogin? userLogin = user.GetUserLogin(loginProvider, providerKey);
            if (userLogin is null)
            {
                Logger.LogError(
                    "Compare exchange and user logins are not in sync for user {UserName}. User is missing a '{LoginProvider}' login which is available in the compare exchange",
                    user.UserName,
                    loginProvider
                );
                return null!;
            }

            return new TAspUserLogin
            {
                UserId = user.Id,
                LoginProvider = userLogin.LoginProvider,
                ProviderKey = userLogin.ProviderKey,
                ProviderDisplayName = userLogin.ProviderDisplayName,
            };
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
        protected override Task<TAspUserRole> FindUserRoleAsync(
            string userId,
            string roleId,
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

            return Queryable.Select(
                    DocumentSession.Query<TUser>()
                        .Where(
                            user =>
                                user.Id.Equals(userId)
                                && user.Roles.Any(rId => rId.Equals(roleId))
                        ), user => new TAspUserRole
                    {
                        UserId = user.Id,
                        RoleId = roleId,
                    }
                )
                .FirstOrDefaultAsync(cancellationToken);
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

        private static string CreateLoginReservationUniqueValue(string loginProvider, string providerKey)
        {
            return $"{loginProvider}/{providerKey}";
        }
    }
}