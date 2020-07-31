using Microsoft.AspNetCore.Identity;

namespace Mcrio.AspNetCore.Identity.RavenDb.Model.User
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
        /// Gets or sets the LoginProvider this token is from.
        /// </summary>
        public string LoginProvider { get; set; } = null!;

        /// <summary>
        /// Gets or sets the name of the token.
        /// </summary>
        public string Name { get; set; } = null!;

        /// <summary>
        /// Gets or sets the token value.
        /// </summary>
        [ProtectedPersonalData]
        public string Value { get; set; } = null!;
    }
}