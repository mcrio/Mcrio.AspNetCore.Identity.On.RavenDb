namespace Mcrio.AspNetCore.Identity.RavenDb.Model
{
    public class PropertyChange<T>
    {
        internal PropertyChange(T oldValue, T newValue)
        {
            OldValue = oldValue;
            NewValue = newValue;
        }

        internal T OldValue { get; }

        internal T NewValue { get; }
    }
}