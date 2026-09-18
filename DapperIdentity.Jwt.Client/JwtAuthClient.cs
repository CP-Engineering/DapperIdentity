using CPE.DapperIdentity.Abstractions.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace CPE.DapperIdentity.Jwt.Client
{
    /// <summary>
    /// HTTP client for the server's JWT endpoints: login, refresh, forgot-password and reset.
    /// </summary>
    public class JwtAuthClient
    {
        private static string AuthServerSectionName = "AuthServer";
        private static string AuthServerEndpoint = "Endpoint";

        private static readonly JsonSerializerOptions CaseInsensitive =
            new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        /// <summary>Base address of the authentication server.</summary>
        public Uri Endpoint { get; set; }

        private readonly ILogger<JwtAuthClient>? _logger;

        /// <summary>Reads the auth server address from configuration.</summary>
        /// <param name="configuration">
        /// Must contain an <c>AuthServer:Endpoint</c> value; the constructor throws without it.
        /// </param>
        /// <param name="logger">
        /// Optional so this stays constructible without a logging stack. The DI container supplies
        /// one in any host that has logging registered, which is every ASP.NET Core and Blazor app.
        /// </param>
        public JwtAuthClient(IConfiguration configuration, ILogger<JwtAuthClient>? logger = null)
        {
            _logger = logger;
            var authSection = configuration.GetSection(AuthServerSectionName);
            if (!authSection.Exists()) throw new Exception($"Configuration/AppSettings does not contain section: {AuthServerSectionName}.");

            var address = authSection[AuthServerEndpoint];

            if (string.IsNullOrWhiteSpace(address)) throw new Exception($"{AuthServerEndpoint} property is null/empty");
            Endpoint = new Uri(address);

        }

        /// <summary>Authenticates a user against the server.</summary>
        /// <param name="userForAuthentication">The credentials to present.</param>
        /// <returns>
        /// A result carrying tokens, or the reason there are none. Network failures are not
        /// caught here and surface as exceptions.
        /// </returns>
        public async Task<AuthResult> Login(AuthRequest userForAuthentication)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = Endpoint;

                var content = JsonSerializer.Serialize(userForAuthentication);
                var bodyContent = new StringContent(content, Encoding.UTF8, "application/json");
                var req = new HttpRequestMessage(HttpMethod.Post, "api/jwtauth/login");
                req.Content = bodyContent;

                var authResult = await client.SendAsync(req);
                if (!authResult.IsSuccessStatusCode)
                {
                    return AuthResult.Failed(ClassifyStatus(authResult.StatusCode, "login"));
                }

                var authContent = await authResult.Content.ReadAsStringAsync();
                return ToAuthResult(authContent, "login");
            }
        }

        /// <summary>Authenticates a user from a bare username and password.</summary>
        /// <param name="username">The account's email address.</param>
        /// <param name="password">The account's password.</param>
        /// <returns>A result carrying tokens, or the reason there are none.</returns>
        public async Task<AuthResult> Login(string username, string password)
        {
            return await Login(new AuthRequest { Email = username, Password = password });
        }

        /// <summary>Exchanges an expiring token pair for a fresh one.</summary>
        /// <param name="refreshObject">The current access token and refresh token.</param>
        /// <returns>A result carrying new tokens, or the reason there are none.</returns>
        public async Task<AuthResult> RefreshToken(RefreshTokenDto refreshObject)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = Endpoint;

                var content = JsonSerializer.Serialize(refreshObject);
                var bodyContent = new StringContent(content, Encoding.UTF8, "application/json");
                var req = new HttpRequestMessage(HttpMethod.Post, "api/jwtauth/refresh");
                req.Content = bodyContent;

                var authResult = await client.SendAsync(req);
                if (!authResult.IsSuccessStatusCode)
                {
                    return AuthResult.Failed(ClassifyStatus(authResult.StatusCode, "refresh"));
                }

                var authContent = await authResult.Content.ReadAsStringAsync();
                return ToAuthResult(authContent, "refresh");
            }
        }

        /// <summary>
        /// Turns a successful response body into a result, mapping the wire model rather than
        /// carrying it forward.
        /// </summary>
        /// <remarks>
        /// A 200 with an unreadable or token-less body is a server fault, not a credentials
        /// problem, so it is reported as <see cref="AuthFailure.MalformedResponse"/> rather than
        /// being flattened into "login failed" the way an empty response used to be.
        /// </remarks>
        private AuthResult ToAuthResult(string body, string operation)
        {
            AuthResponse? response;
            try
            {
                response = JsonSerializer.Deserialize<AuthResponse>(body, CaseInsensitive);
            }
            catch (JsonException ex)
            {
                _logger?.LogWarning(ex, "The {Operation} response from {Endpoint} was not valid JSON.", operation, Endpoint);
                return AuthResult.Failed(AuthFailure.MalformedResponse);
            }

            // Deserialize returns null for a literal "null" body, and a body with no token is
            // equally unusable - both mean the server said 200 but gave us nothing to sign in with.
            if (response is null || string.IsNullOrWhiteSpace(response.Token))
            {
                _logger?.LogWarning("The {Operation} response from {Endpoint} carried no access token.", operation, Endpoint);
                return AuthResult.Failed(AuthFailure.MalformedResponse);
            }

            return AuthResult.Success(new AuthTokens(
                response.Token,
                response.RefreshToken,
                response.Username,
                response.Email));
        }

        /// <summary>Maps an unsuccessful HTTP status onto a failure reason.</summary>
        private AuthFailure ClassifyStatus(HttpStatusCode status, string operation)
        {
            // 400 and 401 are both how this server declines an attempt; anything else is the
            // server or the route misbehaving, which the caller may want to retry rather than
            // re-prompt for a password.
            if (status == HttpStatusCode.Unauthorized || status == HttpStatusCode.BadRequest)
            {
                return AuthFailure.InvalidCredentials;
            }

            _logger?.LogWarning("The {Operation} request to {Endpoint} returned {Status}.", operation, Endpoint, (int)status);
            return AuthFailure.ServerError;
        }

        /// <summary>Asks the server to start a password reset for the given address.</summary>
        /// <param name="username">The account's email address.</param>
        /// <returns><see langword="false"/> only when the request never completed.</returns>
        public async Task<bool> ForgotPassword(string username)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = Endpoint;

                var requestcontent = new ForgotPasswordRequest() { Email = username };
                var content = JsonSerializer.Serialize(requestcontent);
                var bodyContent = new StringContent(content, Encoding.UTF8, "application/json");
                var req = new HttpRequestMessage(HttpMethod.Post, "api/jwtauth/forgotpassword");
                req.Content = bodyContent;

                try
                {
                    // Deliberately true whichever status comes back, and not a ToDo. The server's
                    // ForgotPassword returns 200 for an unknown or unconfirmed email precisely so
                    // the endpoint cannot be used to discover which accounts exist
                    // (JwtAuthController.ForgotPassword). A client that reported "no such user"
                    // would hand back the very distinction the server refuses to make.
                    //
                    // false therefore means one thing only: the request never completed.
                    await client.SendAsync(req);
                    return true;
                }
                catch (Exception ex)
                {
                    // Was swallowed silently. The caller only learns that something failed, so
                    // without this the reason - DNS, TLS, timeout, wrong endpoint - was lost.
                    _logger?.LogWarning(ex, "ForgotPassword request to {Endpoint} did not complete.", Endpoint);
                    return false;
                }

            }
        }

        /// <summary>Completes a password reset with the code the user received.</summary>
        /// <param name="userName">The account's email address.</param>
        /// <param name="password">The new password.</param>
        /// <param name="code">The reset code issued by the server.</param>
        /// <returns><see langword="true"/> when the server accepted the reset.</returns>
        public async Task<bool> ResetPassword(string userName, string password, string code)
        {
            using (var client = new HttpClient())
            {
                client.BaseAddress = Endpoint;

                var requestcontent = new ResetPasswordRequest() { Email = userName, Code = code, Password = password, ConfirmPassword = password };
                var content = JsonSerializer.Serialize(requestcontent);
                var bodyContent = new StringContent(content, Encoding.UTF8, "application/json");
                var req = new HttpRequestMessage(HttpMethod.Post, "api/jwtauth/ResetPassword");
                req.Content = bodyContent;

                var authResult = await client.SendAsync(req);
                return authResult.IsSuccessStatusCode;
            }
        }

    }
}
