namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User
{
    /// <summary>
    /// Represents login information and source for a user record.
    /// </summary>
    public class RavenIdentityUserLogin
    {
        /// <summary>
        /// Creates a new instance of <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <param name="loginProvider">The provider associated with this login information.</param>
        /// <param name="providerKey">The unique identifier for this user provided by the login provider.</param>
        /// <param name="displayName">The display name for this user provided by the login provider.</param>
        public RavenIdentityUserLogin(string loginProvider, string providerKey, string displayName)
        {
            LoginProvider = loginProvider;
            ProviderKey = providerKey;
            ProviderDisplayName = displayName;
        }

        private RavenIdentityUserLogin()
        {
        }

        /// <summary>
        /// Sets the provider for this instance of <see cref="UserLoginInfo"/>.
        /// </summary>
        /// <value>The provider for the this instance of <see cref="UserLoginInfo"/>.</value>
        /// <remarks>
        /// Examples of the provider may be Local, Facebook, Google, etc.
        /// </remarks>
        public string LoginProvider { get; private set; } = default!;

        /// <summary>
        /// Sets the unique identifier for the user identity user provided by the login provider.
        /// </summary>
        /// <value>
        /// The unique identifier for the user identity user provided by the login provider.
        /// </value>
        /// <remarks>
        /// This would be unique per provider, examples may be @microsoft as a Twitter provider key.
        /// </remarks>
        public string ProviderKey { get; private set; } = default!;

        /// <summary>
        /// Sets the display name for the provider.
        /// </summary>
        /// <value>
        /// The display name for the provider.
        /// </value>
        public string ProviderDisplayName { get; private set; } = default!;
    }
}