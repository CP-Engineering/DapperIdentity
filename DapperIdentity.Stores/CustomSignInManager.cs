using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;


namespace CPE.DapperIdentity.Stores
{
    /// <summary>
    /// <see cref="SignInManager{TUser}"/> extended with the library's own IsEnabled check.
    /// </summary>
    /// <remarks>
    /// The only behaviour added is in <see cref="PreSignInCheck"/>: a user whose IsEnabled column
    /// is false is refused even when the password is correct. Register it in place of the stock
    /// sign-in manager, or the column has no effect.
    /// </remarks>
    public class CustomSignInManager : SignInManager<IdentityUser> 
    {
        /// <summary>Passes every dependency through to the base sign-in manager.</summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="contextAccessor">Accessor for the current HTTP context.</param>
        /// <param name="claimsFactory">Builds the claims principal for a signed-in user.</param>
        /// <param name="optionsAccessor">The configured Identity options.</param>
        /// <param name="logger">Logger for the base sign-in manager.</param>
        /// <param name="schemes">The registered authentication schemes.</param>
        /// <param name="confirmation">Decides whether a user counts as confirmed.</param>
        public CustomSignInManager(UserManager<IdentityUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<IdentityUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<IdentityUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<IdentityUser> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        { }


        /// <summary>
        /// Used to ensure that a user is allowed to sign in.
        /// Added IsEnabled Check
        /// </summary>
        /// <param name="user">The user</param>
        /// <returns>Null if the user should be allowed to sign in, otherwise the SignInResult why they should be denied.</returns>
        protected override async Task<SignInResult?> PreSignInCheck(IdentityUser user)
        {
            if (!await CanSignInAsync(user))
            {
                return SignInResult.NotAllowed;
            }
            if (await IsLockedOut(user))
            {
                return await LockedOut(user);
            }
            if (!user.IsEnabled)
            {
                return SignInResult.NotAllowed;
            }

            return null;
        }
    }
}
