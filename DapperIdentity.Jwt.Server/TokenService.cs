using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using IdentityRole = CPE.DapperIdentity.Stores.Models.CustomIdentityRole;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
//using System.IdentityModel.Tokens.Jwt; Used directly below

namespace CPE.DapperIdentity.Jwt.Server;

/// <summary>
/// Issues the access and refresh tokens the JWT endpoints hand out, and reads the principal back
/// out of an expired one.
/// </summary>
/// <remarks>
/// Settings come from the <c>JwtTokenSettings</c> configuration section, which is required - the
/// constructor throws if it is absent. Tokens are signed with HMAC-SHA256 using the symmetric key
/// from that section, so every service that validates these tokens must hold the same key.
/// </remarks>
public class TokenService
{

    private readonly ILogger<TokenService> _logger;

    private JwtSettings _JwtSettings;

    private IClaimsService _ClaimsService;

    private IUserClaimStore<IdentityUser> _userClaimStore;


    /// <summary>Reads the JWT settings from configuration and captures the claim sources.</summary>
    /// <param name="logger">Logger for token creation and claim-building failures.</param>
    /// <param name="configuration">
    /// Must contain a <c>JwtTokenSettings</c> section; the constructor throws without it.
    /// </param>
    /// <param name="claimStore">
    /// Store the per-user claims are read from when a token is built.
    /// </param>
    /// <param name="claimsService">
    /// Optional hook for claims the consumer computes rather than stores. Omit it and only stored
    /// claims and roles reach the token.
    /// </param>
    public TokenService(ILogger<TokenService> logger,
                        IConfiguration configuration,
                        IUserClaimStore<IdentityUser> claimStore,
                        IClaimsService claimsService = null)
    {
        _logger = logger;
        _JwtSettings = new JwtSettings(configuration);
        _ClaimsService = claimsService;
        _userClaimStore = claimStore;
    }

    /// <summary>
    /// Builds and signs an access token for the user.
    /// </summary>
    /// <remarks>
    /// The token carries the standard registered claims, one role claim per entry in
    /// <paramref name="roles"/>, everything in the user's claim store, and anything the optional
    /// <see cref="IClaimsService"/> contributes. It expires after the configured
    /// <c>JwtExpireSeconds</c>.
    /// </remarks>
    /// <param name="user">The user the token is issued for.</param>
    /// <param name="roles">Role names to write as role claims.</param>
    /// <returns>The signed JWT.</returns>
    public async ValueTask<string> CreateToken(IdentityUser user, IEnumerable<string> roles)
    {
        var expiration = DateTime.UtcNow + _JwtSettings.ExpirationTime; //AddMinutes(ExpirationMinutes);
        var tokenHandler = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler();

        var d = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(await CreateClaims(user, roles)),
            SigningCredentials = CreateSigningCredentials(),
            Expires = expiration,
        };
        _logger.LogInformation("JWT Token created");

        return tokenHandler.CreateToken(d);// WriteToken(token);
    }



    /// <summary>
    /// Assembles every claim that goes into an access token, from three sources.
    /// </summary>
    /// <remarks>
    /// In order: the registered claims (sub, jti, iat, iss, aud) plus name, email and a duplicate
    /// UserId claim; one role claim per entry in <paramref name="usersRoles"/>; whatever the
    /// optional <see cref="IClaimsService"/> returns; and finally the user's stored claims. Both
    /// optional sources are null-checked, so a host that registers neither still gets a usable
    /// token. Nothing de-duplicates, so a stored claim that repeats a role appears twice.
    /// </remarks>
    /// <param name="user">The user the token is for.</param>
    /// <param name="usersRoles">Role names to write as role claims.</param>
    /// <returns>The assembled claims.</returns>
    private async ValueTask<List<Claim>> CreateClaims(IdentityUser user, IEnumerable<string> usersRoles)
    {

        try
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),//user is the "subject" so we store userid here
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new Claim(JwtRegisteredClaimNames.Iss, _JwtSettings.ValidIssuer),
                new Claim(JwtRegisteredClaimNames.Aud, _JwtSettings.ValidAudience),
                //new Claim(ClaimTypes.NameIdentifier, user.Id),//username does not work when enables.
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("UserId",user.Id)
            };

            foreach (var role in usersRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                //claims.Add(new Claim("roles", role));
            }

            if (_ClaimsService is not null) 
            {
                var userClaims = await _ClaimsService.ClaimsToAdd(user);
                claims.AddRange(userClaims);
            }

            if (_userClaimStore is not null)
            {
                var userClaims = await _userClaimStore.GetClaimsAsync(user, new CancellationToken());
                claims.AddRange(userClaims);
            }


            return claims;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            _logger.LogCritical(e,"Error creating claims");
            throw;
        }
    }

    /// <summary>Builds the HMAC-SHA256 credentials every token is signed with.</summary>
    /// <remarks>
    /// Symmetric, so the signing key and the validating key are the same secret. Any service that
    /// holds it can mint tokens this application will accept.
    /// </remarks>
    /// <returns>Signing credentials over the configured symmetric key.</returns>
    private SigningCredentials CreateSigningCredentials()
    {
        var symmetricSecurityKey = _JwtSettings.SymmetricSecurityKey;

        return new SigningCredentials(
            new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(symmetricSecurityKey)
            ),
            SecurityAlgorithms.HmacSha256
        );
    }

    /// <summary>
    /// Generates a random token and new expiration date for the refresh token
    /// </summary>
    /// <returns>
    /// The refresh token (32 cryptographically random bytes, base64) and when it stops being
    /// accepted, <c>RefreshTokenLifeDays</c> from now. Storing it against the user is the caller's
    /// job; this method only mints it.
    /// </returns>
    public (string token, DateTime expiration) GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return (Convert.ToBase64String(randomNumber), DateTime.Now + _JwtSettings.RefreshTokenLife);
        }
    }

    /// <summary>
    /// Reads the principal out of a token whose lifetime has passed, validating the signature and
    /// the issuer but not the expiry.
    /// </summary>
    /// <remarks>
    /// Nothing in this library calls this. The refresh endpoint uses
    /// <see cref="GetPrincipalFromExpiredToken2"/>, which is the same routine with issuer
    /// validation turned off - so of the two, the stricter one is the unused one.
    /// </remarks>
    /// <param name="token">The expired access token.</param>
    /// <returns>The principal the token describes.</returns>
    /// <exception cref="SecurityTokenException">
    /// The token is not a JWT, or is not signed with HMAC-SHA256.
    /// </exception>
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_JwtSettings.SymmetricSecurityKey)),
            ValidateLifetime = false,
            ValidIssuer = _JwtSettings.ValidIssuer,
            ValidAudience = _JwtSettings.ValidAudience,
            ValidAudiences = new[] {_JwtSettings.ValidAudience}
        };
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        var jwtSecurityToken = securityToken as System.IdentityModel.Tokens.Jwt.JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
            StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    /// <summary>
    /// Reads the principal out of an expired token, validating only the signature.
    /// </summary>
    /// <remarks>
    /// This is what the refresh endpoint calls. Issuer, audience and lifetime are all left
    /// unvalidated, so the only thing standing between a caller and a refreshed session is
    /// possession of a token signed with this service's symmetric key.
    /// </remarks>
    /// <param name="token">The expired access token.</param>
    /// <returns>The principal the token describes.</returns>
    /// <exception cref="SecurityTokenException">
    /// The token is not a JWT, or is not signed with HMAC-SHA256.
    /// </exception>
    public ClaimsPrincipal GetPrincipalFromExpiredToken2(string? token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_JwtSettings.SymmetricSecurityKey)),
            ValidateLifetime = false
        };

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;

    }
    /// <summary>
    /// Typed reader over the required <c>JwtTokenSettings</c> configuration section.
    /// </summary>
    /// <remarks>
    /// The sample below was previously a block comment nested inside this summary, which is not
    /// legal XML - it is why the file emitted CS1587 and two CS1570s. It is a code block now.
    /// <code>
    /// "JwtTokenSettings": {
    ///   "ValidIssuer": "ExampleIssuer",
    ///   "ValidAudience": "ValidAudience",
    ///   "SymmetricSecurityKey": "&lt;a long random string, not this one&gt;",
    ///   "JwtExpireSeconds": 900,
    ///   "RefreshTokenLifeDays": 4
    /// }
    /// </code>
    /// Every accessor uses the null-forgiving operator, so a missing key surfaces as a
    /// NullReferenceException on first use rather than a named configuration error.
    /// </remarks>
    private record JwtSettings
    {

        private IConfiguration _Configuration;


        public JwtSettings(IConfiguration config)
        {
            _Configuration = config.GetRequiredSection("JwtTokenSettings");
        }

        public string ValidIssuer => _Configuration["ValidIssuer"]!;

        public string ValidAudience => _Configuration["ValidAudience"]!;

        public string SymmetricSecurityKey => _Configuration["SymmetricSecurityKey"]!;

        //public string JwtRegisteredClaimNamesSub => _Configuration["JwtRegisteredClaimNamesSub"]!;

        public TimeSpan ExpirationTime => TimeSpan.FromSeconds(double.Parse(_Configuration["JwtExpireSeconds"]!));

        public TimeSpan RefreshTokenLife => TimeSpan.FromDays(double.Parse(_Configuration["RefreshTokenLifeDays"]!));

    }
}