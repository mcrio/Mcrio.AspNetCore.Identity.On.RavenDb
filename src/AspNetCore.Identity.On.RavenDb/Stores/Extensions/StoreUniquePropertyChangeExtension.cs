using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Extensions
{
    /// <summary>
    /// Extension methods that handle unique value reservations for changed properties.
    /// </summary>
    internal static class StoreUniquePropertyChangeExtension
    {
        /// <summary>
        /// If there is a property change that requires uniqueness check, make a new compare exchange
        /// reservation or throw if unique value already exists.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="entityId">Entity id.</param>
        /// <param name="changedPropertyName">Name of property we are checking the change for.</param>
        /// <param name="newPropertyValue">Expected new value for changed property.</param>
        /// <param name="newCompareExchangeUniqueValue">New unique value we want to reserve.</param>
        /// <param name="cmpExchangeReservationType">Compare exchange reservation type.</param>
        /// <returns>Optional property change data if there was a property change and
        /// a successful new compare exchange reservation made.</returns>
        /// <exception cref="UniqueValueExistsException">If new unique value already exists.</exception>
        internal static async Task<PropertyChange<string>?> ReserveIfPropertyChangedAsync(
            this IAsyncDocumentSession documentSession,
            string entityId,
            string changedPropertyName,
            string newPropertyValue,
            string newCompareExchangeUniqueValue,
            RavenDbCompareExchangeExtension.ReservationType cmpExchangeReservationType)
        {
            IDictionary<string, DocumentsChanges[]> whatChanged = documentSession.Advanced.WhatChanged();
            if (whatChanged.ContainsKey(entityId))
            {
                DocumentsChanges? change = whatChanged[entityId]
                    .FirstOrDefault(changes =>
                        changes.Change == DocumentsChanges.ChangeType.FieldChanged
                        && changes.FieldName == changedPropertyName
                    );
                if (change != null)
                {
                    if (newPropertyValue != change.FieldNewValue.ToString())
                    {
                        throw new InvalidOperationException(
                            $"User updated {changedPropertyName} property '{newPropertyValue}' should match change "
                            + $"trackers recorded new value '{change.FieldNewValue}'"
                        );
                    }

                    bool reserved = await documentSession
                        .CreateReservationAsync<string>(
                            cmpExchangeReservationType,
                            newCompareExchangeUniqueValue
                        ).ConfigureAwait(false);
                    if (!reserved)
                    {
                        throw new UniqueValueExistsException(
                            $"Compare exchange unique value {newCompareExchangeUniqueValue} already exists."
                        );
                    }

                    return new PropertyChange<string>(
                        change.FieldOldValue.ToString(),
                        newPropertyValue
                    );
                }
            }

            return null;
        }
    }
}