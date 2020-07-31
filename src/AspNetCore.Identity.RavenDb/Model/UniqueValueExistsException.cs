using System;

namespace Mcrio.AspNetCore.Identity.RavenDb.Model
{
    internal class UniqueValueExistsException : Exception
    {
        internal UniqueValueExistsException(string message)
            : base(message)
        {
        }
    }
}