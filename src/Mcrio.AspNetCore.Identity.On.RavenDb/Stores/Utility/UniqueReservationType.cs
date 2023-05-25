namespace Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Utility
{
    /// <summary>
    /// Unique value reservation types.
    /// </summary>
    public enum UniqueReservationType
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
}