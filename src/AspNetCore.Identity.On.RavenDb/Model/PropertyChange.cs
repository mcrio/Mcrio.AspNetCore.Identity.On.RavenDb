namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model
{
    public class PropertyChange<T>
    {
        internal PropertyChange(T oldPropertyValue, T newPropertyValue)
        {
            OldPropertyValue = oldPropertyValue;
            NewPropertyValue = newPropertyValue;
        }

        internal T OldPropertyValue { get; }

        internal T NewPropertyValue { get; }
    }
}