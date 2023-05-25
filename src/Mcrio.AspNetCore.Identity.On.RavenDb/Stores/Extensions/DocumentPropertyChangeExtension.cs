using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Extensions
{
    /// <summary>
    /// Extension methods that handle document changes.
    /// </summary>
    internal static class DocumentPropertyChangeExtension
    {
        /// <summary>
        /// Checks whether a specific property has changed for given entity.
        /// </summary>
        /// <param name="documentSession">Document session.</param>
        /// <param name="entity">Entity we are checking the property change for.</param>
        /// <param name="changedPropertyName">Name of property we are checking the change for.</param>
        /// <param name="newPropertyValue">Expected new value for changed property.</param>
        /// <param name="propertyChange">Instance of <see cref="PropertyChange{T}"/> when property has changed, NULL otherwise.</param>
        /// <typeparam name="TEntity">Type of entity we are checking the property change for.</typeparam>
        /// <returns>TRUE if property has changed, FALSE otherwise.</returns>
        internal static bool IfPropertyChanged<TEntity>(
            this IAsyncDocumentSession documentSession,
            TEntity entity,
            string changedPropertyName,
            string newPropertyValue,
            out PropertyChange<string>? propertyChange)
            where TEntity : IEntity
        {
            Debug.Assert(
                documentSession.Advanced.IsLoaded(entity.Id),
                "Expected the document to be loaded in the unit of work."
            );

            IDictionary<string, DocumentsChanges[]> whatChanged = documentSession.Advanced.WhatChanged();
            string entityId = entity.Id;

            if (whatChanged.TryGetValue(entityId, out DocumentsChanges[]? documentChanges))
            {
                DocumentsChanges? change = documentChanges?
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

                    propertyChange = new PropertyChange<string>(
                        oldPropertyValue: change.FieldOldValue.ToString(),
                        newPropertyValue: newPropertyValue
                    );
                    return true;
                }
            }

            propertyChange = null;
            return false;
        }
    }
}