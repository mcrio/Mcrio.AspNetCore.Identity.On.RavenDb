using System;
using System.Threading.Tasks;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Extensions
{
    /// <summary>
    /// Provides extension methods to handle RavenDb compare exchange functionality.
    /// </summary>
    internal static class RavenDbCompareExchangeExtension
    {
        private const string IdentityRoleCompareExchangePrefix = "identity/role";
        private const string IdentityUserNameCompareExchangePrefix = "identity/username";
        private const string IdentityEmailCompareExchangePrefix = "identity/email";
        private const string IdentityUserLoginCompareExchangePrefix = "identity/login";

        /// <summary>
        /// Represents different compare exchange reservation types.
        /// </summary>
        internal enum ReservationType
        {
            /// <summary>
            /// Role normalized name reservation.
            /// </summary>
            Role,

            /// <summary>
            /// Username reservation.
            /// </summary>
            Username,

            /// <summary>
            /// Email reservation.
            /// </summary>
            Email,

            /// <summary>
            /// User external login reservation.
            /// </summary>
            Login,
        }

        /// <summary>
        /// Creates a compare exchange reservation.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="reservationType">Reservation type.</param>
        /// <param name="expectedCompareExchangeUniqueValue">Compare exchange unique value requested for given reservation type.</param>
        /// <param name="data">Custom data to be stored.</param>
        /// <typeparam name="TValue">Type of data to be stored.</typeparam>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        internal static Task<bool> CreateReservationAsync<TValue>(
            this IAsyncDocumentSession documentSession,
            ReservationType reservationType,
            string expectedCompareExchangeUniqueValue,
            TValue data = default)
        {
            return CreateReservationAsync(
                documentSession,
                PrepareCompareExchangeKey(GetPrefix(reservationType), expectedCompareExchangeUniqueValue),
                data
            );
        }

        /// <summary>
        /// Removes an existing compare exchange reservation.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="reservationType">Reservation type.</param>
        /// <param name="expectedUniqueValue">Unique value requested for given reservation type.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        internal static Task<bool> RemoveReservationAsync(
            this IAsyncDocumentSession documentSession,
            ReservationType reservationType,
            string expectedUniqueValue)
        {
            string prefix = GetPrefix(reservationType);

            return RemoveReservationAsync(
                documentSession,
                PrepareCompareExchangeKey(prefix, expectedUniqueValue)
            );
        }

        /// <summary>
        /// Retrieves an existing compare exchange value if it exists.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="reservationType">Reservation type.</param>
        /// <param name="expectedUniqueValue">Unique value for the given reservation type.</param>
        /// <typeparam name="TValue">Type of compare exchange data.</typeparam>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        internal static Task<CompareExchangeValue<TValue>?> GetReservationAsync<TValue>(
            this IAsyncDocumentSession documentSession,
            ReservationType reservationType,
            string expectedUniqueValue)
        {
            string prefix = GetPrefix(reservationType);

            return GetReservationAsync<TValue>(
                documentSession,
                PrepareCompareExchangeKey(prefix, expectedUniqueValue)
            );
        }

        private static string GetPrefix(ReservationType reservationType)
        {
            return reservationType switch
            {
                ReservationType.Role => IdentityRoleCompareExchangePrefix,
                ReservationType.Username => IdentityUserNameCompareExchangePrefix,
                ReservationType.Email => IdentityEmailCompareExchangePrefix,
                ReservationType.Login => IdentityUserLoginCompareExchangePrefix,
                _ => throw new Exception($"Unhandled reservation type {reservationType}")
            };
        }

        private static async Task<bool> CreateReservationAsync<TValue>(
            IAsyncDocumentSession documentSession,
            string cmpExchangeKey,
            TValue data = default)
        {
            var documentStore = documentSession.Advanced.DocumentStore;

            CompareExchangeResult<TValue> compareExchangeResult = await documentStore.Operations.SendAsync(
                new PutCompareExchangeValueOperation<TValue>(cmpExchangeKey, data, 0)
            ).ConfigureAwait(false);

            return compareExchangeResult.Successful;
        }

        private static Task<CompareExchangeValue<TValue>?> GetReservationAsync<TValue>(
            IAsyncDocumentSession documentSession,
            string cmpExchangeKey)
        {
            var store = documentSession.Advanced.DocumentStore;
            return store.Operations.SendAsync(
                new GetCompareExchangeValueOperation<TValue>(cmpExchangeKey)
            );
        }

        private static async Task<bool> RemoveReservationAsync(
            IAsyncDocumentSession documentSession,
            string cmpExchangeKey)
        {
            var documentStore = documentSession.Advanced.DocumentStore;

            // get existing in order to get the index
            CompareExchangeValue<string>? existingResult = await GetReservationAsync<string>(
                documentSession,
                cmpExchangeKey
            ).ConfigureAwait(false);

            if (existingResult is null)
            {
                // it does not exist so return positive result
                return true;
            }

            CompareExchangeResult<string> compareExchangeResult = await documentStore.Operations.SendAsync(
                new DeleteCompareExchangeValueOperation<string>(cmpExchangeKey, existingResult.Index)
            ).ConfigureAwait(false);

            return compareExchangeResult.Successful;
        }

        private static string PrepareCompareExchangeKey(string prefix, string expectedUniqueValue)
        {
            return prefix.TrimEnd('/') + '/' + expectedUniqueValue;
        }
    }
}