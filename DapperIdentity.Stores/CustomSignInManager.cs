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
using CPE.DapperIdentity.Stores.SignIn;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;


namespace CPE.DapperIdentity.Stores
{
    /// <summary>
    /// <see cref="SignInManager{TUser}"/> extended with the library's own IsEnabled check.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="PreSignInCheck"/> refuses a user whose IsEnabled column is false even when the
    /// password is correct. Register it in place of the stock sign-in manager, or the column has no effect.
    /// </para>
    /// <para>
    /// It is also the one place sign-ins are reported (<see cref="ISignInReporter"/>): cookie sign-ins
    /// through <see cref="PasswordSignInAsync(string, string, bool, bool)"/>, token endpoints through
    /// <see cref="CheckPasswordByEmailAsync"/>. Token endpoints must use that rather than
    /// <c>UserManager.CheckPasswordAsync</c>, which checks only the password hash and so lets a
    /// disabled, unconfirmed or locked-out user through.
    /// </para>
    /// </remarks>
    public class CustomSignInManager : SignInManager<IdentityUser> 
    {
        private readonly ISignInReporter? _signInReporter;

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

        /// <summary>As the other constructor, and reports every sign-in to <paramref name="signInReporter"/>.</summary>
        /// <param name="userManager">The user manager.</param>
        /// <param name="contextAccessor">Accessor for the current HTTP context.</param>
        /// <param name="claimsFactory">Builds the claims principal for a signed-in user.</param>
        /// <param name="optionsAccessor">The configured Identity options.</param>
        /// <param name="logger">Logger for the base sign-in manager.</param>
        /// <param name="schemes">The registered authentication schemes.</param>
        /// <param name="confirmation">Decides whether a user counts as confirmed.</param>
        /// <param name="signInReporter">Told of each sign-in, so a tool like PortGuardian can ban an address that keeps failing.</param>
        public CustomSignInManager(UserManager<IdentityUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<IdentityUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<IdentityUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<IdentityUser> confirmation,
            ISignInReporter signInReporter) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
        {
            _signInReporter = signInReporter;
        }

        /// <summary>
        /// Signs in by user name, as the base does, and reports the attempt. An unknown name is
        /// reported here because it never reaches the password check.
        /// </summary>
        /// <inheritdoc />
        public override async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            var user = await UserManager.FindByNameAsync(userName);
            if (user is null)
            {
                Report(SignInAttempt.Failure(CurrentContext(), userName, SignInFailure.UnknownUser, "cookie"));
                return SignInResult.Failed;
            }

            var result = await PasswordSignInAsync(user, password, isPersistent, lockoutOnFailure);
            Report(SignInAttempt.FromSignInResult(result, CurrentContext(), userName, "cookie"));
            return result;
        }

        /// <summary>
        /// Checks an email and password the way a sign-in does - enabled, confirmed, not locked out,
        /// then the password - without issuing a cookie, and reports the attempt. For token endpoints,
        /// so they refuse exactly whom a cookie sign-in refuses.
        /// </summary>
        /// <param name="email">The email as typed.</param>
        /// <param name="password">The password as typed.</param>
        /// <param name="path">Which endpoint, for the report.</param>
        /// <returns>The user when the check passed; otherwise no user and the reason in Result.</returns>
        public async Task<(SignInResult Result, IdentityUser? User)> CheckPasswordByEmailAsync(string email, string password, string path = "jwt")
        {
            var user = await UserManager.FindByEmailAsync(email);
            if (user is null)
            {
                Report(SignInAttempt.Failure(CurrentContext(), email, SignInFailure.UnknownUser, path));
                return (SignInResult.Failed, null);
            }

            // No lockout counting, as the cookie sign-in (lockoutOnFailure: false); PortGuardian bans
            // the address instead, which does not let an attacker lock a real user out.
            var result = await CheckPasswordSignInAsync(user, password, lockoutOnFailure: false);
            Report(SignInAttempt.FromSignInResult(result, CurrentContext(), email, path));
            return (result, result.Succeeded ? user : null);
        }

        /// <summary>
        /// Whether the user may sign in now - enabled, confirmed, not locked out. For a token refresh,
        /// which has no password to check but must stop working for a user who was disabled.
        /// </summary>
        /// <param name="user">The user whose token is being refreshed.</param>
        public async Task<bool> AllowsSignInAsync(IdentityUser user) => await PreSignInCheck(user) is null;

        private HttpContext? CurrentContext()
        {
            // The base throws when there is no request (a background job signing someone in); a
            // report without an address is still worth its log line.
            try { return Context; }
            catch (InvalidOperationException) { return null; }
        }

        private void Report(SignInAttempt? attempt)
        {
            if (attempt is null || _signInReporter is null)
                return;
            try
            {
                _signInReporter.Report(attempt);
            }
#pragma warning disable CA1031 // A host's own reporter must not be able to break a sign-in either.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                Logger.LogWarning(ex, "The sign-in reporter failed; the sign-in itself was not affected.");
            }
        }


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
