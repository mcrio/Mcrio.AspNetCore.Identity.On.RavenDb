using System;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model
{
    internal class UniqueValueExistsException : Exception
    {
        internal UniqueValueExistsException(string message)
            : base(message)
        {
        }
    }
}