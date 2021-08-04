using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Model.User
{
    /// <summary>
    /// Class that represents a token the <see cref="RavenIdentityUser{TKey}" /> object can have.
    /// </summary>
    public class RavenIdentityToken
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityToken"/> class.
        /// </summary>
        /// <param name="loginProvider">Login provider this token is from.</param>
        /// <param name="name">Token name.</param>
        /// <param name="value">Token value.</param>
        public RavenIdentityToken(string loginProvider, string name, string value)
        {
            LoginProvider = loginProvider;
            Name = name;
            Value = value;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RavenIdentityToken"/> class.
        /// </summary>
        private RavenIdentityToken()
        {
        }

        /// <summary>
        /// Sets the LoginProvider this token is from.
        /// </summary>
        public string LoginProvider { get; private set; } = null!;

        /// <summary>
        /// Sets the name of the token.
        /// </summary>
        public string Name { get; private set; } = null!;

        /// <summary>
        /// Sets the token value.
        /// </summary>
        [ProtectedPersonalData]
        public string Value { get; private set; } = null!;
    }
}