using System;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility.Exceptions
{
    /// <summary>
    /// Duplicate document exception.
    /// </summary>
    public class DuplicateException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DuplicateException"/> class.
        /// </summary>
        /// <param name="message"></param>
        public DuplicateException(string? message = null)
            : base(message ?? "Item already exists.")
        {
        }
    }
}