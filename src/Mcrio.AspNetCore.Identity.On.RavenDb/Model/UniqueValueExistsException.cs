using System;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model
{
    /// <summary>
    /// Exception indicating that the unique value already exists.
    /// </summary>
    internal class UniqueValueExistsException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UniqueValueExistsException"/> class.
        /// </summary>
        /// <param name="message">Message.</param>
        internal UniqueValueExistsException(string message)
            : base(message)
        {
        }
    }
}