using CPE.DapperIdentity.Stores.Models;
using CPE.DapperIdentity.Abstractions.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using CPE.DapperIdentity.Abstractions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using ForgotPasswordRequest = CPE.DapperIdentity.Abstractions.Models.ForgotPasswordRequest;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;
using ResetPasswordRequest = CPE.DapperIdentity.Abstractions.Models.ResetPasswordRequest;




//https://markjames.dev/blog/jwt-authorization-asp-net-core
//https://www.c-sharpcorner.com/article/jwt-authentication-with-refresh-tokens-in-net-6-0/
namespace CPE.DapperIdentity.Jwt.Server.Controllers;

/// <summary>
/// The JWT authentication endpoints: register, login, refresh, forgot password and reset.
/// </summary>
/// <remarks>
/// Routed at <c>/api/jwtauth</c>. Registered by <c>AddJwtIdentity</c>, which routes this
/// controller and no other from the assembly.
/// </remarks>
[ApiController]
[Route("/api/[controller]")]
//[Route("/[controller]/[action]")]
public class JwtAuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    //private readonly ApplicationDbContext _context;
    private readonly TokenService _tokenService;

    private readonly IAuthEmailSender _EmailSender;

    private readonly ILogger<JwtAuthController> _logger;

    private readonly IAppSettings _AppSettings;

    private readonly AppBaseUrl _AppBaseUrl;

    private readonly PasswordResetRateLimiter _ResetRateLimiter;

    /// <summary>Captures the services the endpoints need.</summary>
    /// <param name="userManager">Identity's user manager.</param>
    /// <param name="tokenService">Issues access and refresh tokens.</param>
    /// <param name="emailSender">Sends the registration and password-reset mails.</param>
    /// <param name="logger">Logger for the endpoints.</param>
    /// <param name="appSettings">
    /// Supplies the application name used in email subjects and bodies.
    /// </param>
    /// <param name="appBaseUrl">The application's public address, used to build the reset link.</param>
    /// <param name="resetRateLimiter">Caps reset attempts per email address.</param>
    public JwtAuthController(UserManager<IdentityUser> userManager,
                             TokenService tokenService,
                             IAuthEmailSender emailSender,
                             ILogger<JwtAuthController> logger,
                             IAppSettings appSettings,
                             AppBaseUrl appBaseUrl,
                             PasswordResetRateLimiter resetRateLimiter)//Todo: Add options, IOptions<JWTControllerOptions> options) //ApplicationDbContext context
    {
        _userManager = userManager;
        //_context = context;
        _EmailSender = emailSender;
        _tokenService = tokenService;
        _logger = logger;
        _AppSettings = appSettings;
        _AppBaseUrl = appBaseUrl;
        _ResetRateLimiter = resetRateLimiter;
    }

    /// <summary>
    /// Creates an account, attaches any supplied claims, and emails a confirmation link.
    /// </summary>
    /// <remarks>
    /// Requires an authenticated caller - this is an admin-style endpoint that creates accounts
    /// for other people, not open self-registration.
    /// </remarks>
    /// <param name="request">The account to create.</param>
    /// <returns>The created user on success, or the model-state errors on a bad request.</returns>
    [Authorize]
    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var result = await _userManager.CreateAsync(
            new IdentityUser
            {
                UserName = request.Username,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                IsEnabled = true
            },
            request.Password!
        );

        if (result.Succeeded)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            request.Id = user.Id;
            request.Password = "";

            //add claims
            List<Claim> claims = new List<Claim>();
            foreach (var item in request.Claims)
            {
                claims.Add(new Claim(item.Key, item.Value));
            }
            await _userManager.AddClaimsAsync(user, claims);

            //send email
            await SendRegistrationEmail(user, $"{_AppSettings.ApplicationName}: Welcome! User Registration", $"Welcome! You have been registered to access {_AppSettings.ApplicationName}! Complete your registration by");

            //return
            return CreatedAtAction(nameof(Register), new { email = request.Email,/* role = request.Role */}, request);
        }

        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(error.Code, error.Description);
        }

        return BadRequest(ModelState);
    }

    /// <summary>
    /// Mints a password-reset token and emails the user a link to set their password.
    /// </summary>
    /// <remarks>
    /// Shared by registration and forgot-password, which is why the wording is parameterised
    /// rather than fixed. The link is built from the configured <see cref="AppBaseUrl"/> and
    /// never from the request: until 2026-09-18 it came from the <c>Referer</c> header, which
    /// meant an anonymous caller could choose the domain a real reset token was mailed to.
    /// </remarks>
    /// <param name="user">The account the reset link is for.</param>
    /// <param name="subject">The email subject line.</param>
    /// <param name="bodyPrefix">Text placed before "clicking here" in the body.</param>
    private async Task SendRegistrationEmail(IdentityUser user, string subject, string bodyPrefix)
    {
        // For more information on how to enable account confirmation and password reset please 
        // visit https://go.microsoft.com/fwlink/?LinkID=532713
        var code = await _userManager.GeneratePasswordResetTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var resetPage = _AppBaseUrl.PathTo("Account/PasswordReset");
        var callbackUrl = QueryHelpers.AddQueryString(resetPage.AbsoluteUri, "code", code);

        //Send Email With Callback URL to reset the password
        await _EmailSender.SendEmailAsync(
            user.Email,
            subject,
            $"{bodyPrefix} <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

    }


    /// <summary>
    /// Forgot Password Endpoint To Initiate a Password Reset
    /// </summary>
    /// <param name="forgotPasswordRequest"></param>
    /// <returns></returns>
    [AllowAnonymous]
    [HttpPost]
    [Route("Forgot")]
    [Route("ForgotPassword")]
    public async Task<ActionResult> ForgotPassword([FromBody] ForgotPasswordRequest forgotPasswordRequest)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        // Before the lookup, and regardless of whether the account exists, so that a 429 cannot
        // be used to tell a registered address from an unregistered one.
        if (!_ResetRateLimiter.TryAcquire(forgotPasswordRequest.Email))
        {
            _logger.LogWarning("'Forgot Password' rate limit reached for an address; request rejected.");
            return StatusCode(StatusCodes.Status429TooManyRequests);
        }

        var user = await _userManager.FindByEmailAsync(forgotPasswordRequest.Email);
        if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
        {
            // Don't reveal that the user does not exist or is not confirmed
            _logger.LogInformation($"'Forgot Password' flow rejected for user: {forgotPasswordRequest.Email}. User is not found or email is not confirmed.");
            return Ok();
        }

        try
        {
            await SendRegistrationEmail(user, $"{_AppSettings.ApplicationName}: Reset Password", "Please reset your password by");

        }
        catch (Exception ex)
        {
            // The caller still gets 200 - telling them the send failed would tell them the
            // account exists. The operator needs to know, though: before this carried the user
            // id, a mail outage was indistinguishable from a quiet success in the log.
            _logger.LogError(ex, "'Forgot Password' email could not be sent for user {UserId}.", user.Id);
        }

        return Ok();

    }

    /// <summary>
    /// This endpoints is called to reset the password
    /// </summary>
    /// <param name="passwordResetRequest"></param>
    /// <returns></returns>
    [AllowAnonymous]
    [HttpPost]
    [Route("ResetPassword")]
    public async Task<ActionResult> ResetPassword([FromBody] ResetPasswordRequest passwordResetRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // Shares the forgot-password budget, so guessing at reset codes costs the same attempts
        // as asking for them.
        if (!_ResetRateLimiter.TryAcquire(passwordResetRequest.Email))
        {
            _logger.LogWarning("'Reset Password' rate limit reached for an address; request rejected.");
            return StatusCode(StatusCodes.Status429TooManyRequests);
        }

        var user = await _userManager.FindByEmailAsync(passwordResetRequest.Email);
        if (user == null)
        {
            // Don't reveal that the user does not exist
            return RedirectToPage("./ResetPasswordConfirmation");
        }

        var codeB = WebEncoders.Base64UrlDecode(passwordResetRequest.Code);

        var code = Encoding.UTF8.GetString(codeB);

        var result = await _userManager.ResetPasswordAsync(user, code, passwordResetRequest.Password);
        if (result.Succeeded)
        {
            await _EmailSender.SendEmailAsync(passwordResetRequest.Email, "Password Reset Successful", "Your password was successfully reset. If you did not change your password, please contact application administrator.");
            return Ok("Password Reset Successful");
            //return RedirectToPage("./ResetPasswordConfirmation");
        }

        foreach (var error in result.Errors)
        {
            _logger.LogError($"Error in API 'ResetPassword: User:{passwordResetRequest.Email} {error.Code} - {error.Description}");
            ModelState.AddModelError(string.Empty, error.Description);
        }
        return BadRequest(ModelState);
    }


    /// <summary>
    /// Login Method
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    [AllowAnonymous]
    [HttpPost]
    [Route("login")]
    public async Task<ActionResult<AuthResponse>> Authenticate([FromBody] AuthRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var managedUser = await _userManager.FindByEmailAsync(request.Email!);
        if (managedUser == null)
        {
            return BadRequest("Bad credentials");
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(managedUser, request.Password!);
        if (!isPasswordValid)
        {
            return BadRequest("Bad credentials");
        }

        var userInDb = managedUser; //why search again?//_userManager.Users.FirstOrDefault(u=>u.Email==) //_context.Users.FirstOrDefault(u => u.Email == request.Email);

        if (userInDb is null)
        {
            return Unauthorized();
        }

        var roles = await _userManager.GetRolesAsync(userInDb);
        var accessToken = await _tokenService.CreateToken(userInDb, roles);

        var refreshTokenInfo = _tokenService.GenerateRefreshToken();
        userInDb.RefreshToken = refreshTokenInfo.token;
        userInDb.RefreshTokenExpireTime = refreshTokenInfo.expiration;
        await _userManager.UpdateAsync(userInDb);//persist the refresh token and expiration in database each time we login

        return Ok(new AuthResponse
        {
            Username = userInDb.UserName,
            Email = userInDb.Email,
            Token = accessToken,
            RefreshToken = userInDb.RefreshToken
        });
    }

    /// <summary>
    /// Exchanges an expired access token and its refresh token for a new pair.
    /// </summary>
    /// <remarks>
    /// The access token is read with <c>GetPrincipalFromExpiredToken2</c>, which validates the
    /// signature only - so the refresh token stored against the user, and its expiry, are what
    /// actually gate this endpoint. A successful refresh rotates both tokens.
    /// </remarks>
    /// <param name="tokenDto">The expired access token and the refresh token issued with it.</param>
    /// <returns>
    /// A new token pair, or 400 when the access token is unreadable, the user is unknown, the
    /// refresh token does not match, or it has expired. All four answer alike on purpose.
    /// </returns>
    [AllowAnonymous]
    [HttpPost]
    [Route("refresh")]
    public async Task<ActionResult<AuthResponse>> Refresh([FromBody] RefreshTokenDto tokenDto)
    {

        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        /*if (tokenDto is null)
        {
            return BadRequest(new AuthResponseDto { IsAuthSuccessful = false, ErrorMessage = "Invalid client request" });
        }
        */

        var principal = _tokenService.GetPrincipalFromExpiredToken2(tokenDto.Token);
        if (principal is null)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var username = principal.Identity!.Name; //do we need to null check on Identity?
        var user = await _userManager.FindByNameAsync(username);// EmailAsync(username);
        if (user == null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpireTime <= DateTime.Now)
            return BadRequest("Invalid access token or refresh token");//return BadRequest(new AuthResponseDto { IsAuthSuccessful = false, ErrorMessage = "Invalid client request" });

        var roles = await _userManager.GetRolesAsync(user);

        //Create a new Token
        var token = await _tokenService.CreateToken(user, roles);

        //Refresh Token
        var tokenInfo = _tokenService.GenerateRefreshToken();
        user.RefreshToken = tokenInfo.token;
        user.RefreshTokenExpireTime = tokenInfo.expiration;
        await _userManager.UpdateAsync(user);

        return Ok(new AuthResponse() { Email = user.Email, RefreshToken = user.RefreshToken, Token = token, Username = user.UserName });
    }

}
