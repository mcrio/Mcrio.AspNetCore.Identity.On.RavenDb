using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility
{
    /// <summary>
    /// Provides extension methods to handle RavenDb compare exchange functionality.
    /// </summary>
    public class CompareExchangeUtility
    {
        private readonly IAsyncDocumentSession _documentSession;

        /// <summary>
        /// Initializes a new instance of the <see cref="CompareExchangeUtility"/> class.
        /// </summary>
        /// <param name="documentSession"></param>
        public CompareExchangeUtility(IAsyncDocumentSession documentSession)
        {
            _documentSession = documentSession;
        }

        /// <summary>
        /// Creates the compare exchange key for th given reservation type, entity and unique value.
        /// </summary>
        /// <param name="reservationType">Type of reservation.</param>
        /// <param name="expectedUniqueValue">The unique value.</param>
        /// <returns>The complete compare exchange key.</returns>
        public virtual string CreateCompareExchangeKey(
            UniqueReservationType reservationType,
            string expectedUniqueValue)
        {
            if (string.IsNullOrWhiteSpace(expectedUniqueValue))
            {
                throw new ArgumentException(
                    $"Unexpected empty value for {nameof(expectedUniqueValue)} in {nameof(CreateCompareExchangeKey)}"
                );
            }

            string prefix = reservationType switch
            {
                UniqueReservationType.Role => "idnt/role",
                UniqueReservationType.Username => "idnt/uname",
                UniqueReservationType.Email => "idnt/email",
                UniqueReservationType.Login => "idnt/login",
                _ => throw new Exception($"Unhandled reservation type {reservationType}")
            };
            return $"{prefix.TrimEnd('/')}/{expectedUniqueValue}";
        }

        /// <summary>
        /// Prepare reservation deletion as part of a cluster wide transaction.
        /// </summary>
        /// <param name="uniqueReservationType"></param>
        /// <param name="uniqueValueNormalized"></param>
        /// <param name="logger"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>Instance of <see cref="Task"/>.</returns>
        internal async Task PrepareReservationForRemovalAsync(
            UniqueReservationType uniqueReservationType,
            string uniqueValueNormalized,
            ILogger logger,
            CancellationToken cancellationToken)
        {
            Debug.Assert(
                ((AsyncDocumentSession)_documentSession).TransactionMode == TransactionMode.ClusterWide,
                "Expected cluster wide transaction mode"
            );

            if (string.IsNullOrWhiteSpace(uniqueValueNormalized))
            {
                throw new ArgumentException(
                    $"Unexpected empty value for {nameof(uniqueValueNormalized)} in {nameof(PrepareReservationForRemovalAsync)}"
                );
            }

            string compareExchangeKey = CreateCompareExchangeKey(
                uniqueReservationType,
                uniqueValueNormalized
            );
            CompareExchangeValue<string>? compareExchange = await _documentSession
                .Advanced
                .ClusterTransaction
                .GetCompareExchangeValueAsync<string>(compareExchangeKey, cancellationToken)
                .ConfigureAwait(false);
            if (compareExchange != null)
            {
                _documentSession.Advanced.ClusterTransaction.DeleteCompareExchangeValue(
                    compareExchange
                );
            }
            else
            {
                logger.LogWarning(
                    "On {} old reservation delete, unexpectedly missing compare exchange reservation for value {}",
                    uniqueReservationType.ToString(),
                    uniqueValueNormalized
                );
            }
        }

        /// <summary>
        /// Prepare reservation update by checking if provided new value already exists, and if it doesn't
        /// mark old reservation for deletion and add new reservation.
        /// </summary>
        /// <param name="uniqueReservationType"></param>
        /// <param name="newUniqueValueNormalized"></param>
        /// <param name="oldUniqueValueNormalized"></param>
        /// <param name="compareExchangeValue">Value that will be assigned to the compare exchange.</param>
        /// <param name="errorDescriber"></param>
        /// <param name="logger"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>Identity error in case of a failure, NULL otherwise.</returns>
        internal async Task<IdentityError?> PrepareReservationUpdateInUnitOfWorkAsync(
            UniqueReservationType uniqueReservationType,
            string newUniqueValueNormalized,
            string oldUniqueValueNormalized,
            string compareExchangeValue,
            IdentityErrorDescriber errorDescriber,
            ILogger logger,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(newUniqueValueNormalized))
            {
                throw new ArgumentException(
                    $"Unexpected empty value for {nameof(newUniqueValueNormalized)} in {nameof(PrepareReservationUpdateInUnitOfWorkAsync)}");
            }

            if (string.IsNullOrWhiteSpace(oldUniqueValueNormalized))
            {
                throw new ArgumentException(
                    $"Unexpected empty value for {nameof(oldUniqueValueNormalized)} in {nameof(PrepareReservationUpdateInUnitOfWorkAsync)}");
            }

            Debug.Assert(
                ((AsyncDocumentSession)_documentSession).TransactionMode == TransactionMode.ClusterWide,
                "Expected cluster wide transaction mode"
            );

            // check if new value is unique
            string newValueCompareExchangeKey = CreateCompareExchangeKey(
                uniqueReservationType,
                newUniqueValueNormalized
            );
            CompareExchangeValue<string>? existingCompareExchangeWithNewValue = await _documentSession
                .Advanced
                .ClusterTransaction
                .GetCompareExchangeValueAsync<string>(newValueCompareExchangeKey, cancellationToken)
                .ConfigureAwait(false);

            if (existingCompareExchangeWithNewValue != null)
            {
                logger.LogInformation(
                    "Failed reserving {} {} as already exists",
                    uniqueReservationType.ToString(),
                    newUniqueValueNormalized
                );
                switch (uniqueReservationType)
                {
                    case UniqueReservationType.Role:
                        return errorDescriber.DuplicateRoleName(newUniqueValueNormalized);
                    case UniqueReservationType.Username:
                        return errorDescriber.DuplicateUserName(newUniqueValueNormalized);
                    case UniqueReservationType.Email:
                        return errorDescriber.DuplicateEmail(newUniqueValueNormalized);
                    case UniqueReservationType.Login:
                    default:
                        return errorDescriber.ConcurrencyFailure();
                }
            }

            await PrepareReservationForRemovalAsync(
                uniqueReservationType,
                oldUniqueValueNormalized,
                logger,
                cancellationToken
            ).ConfigureAwait(false);

            // prepare new reservation
            _documentSession
                .Advanced
                .ClusterTransaction
                .CreateCompareExchangeValue(
                    newValueCompareExchangeKey,
                    compareExchangeValue
                );

            return null;
        }
    }
}