using Blazored.LocalStorage;
using CPE.DapperIdentity.Abstractions.Models;
using System.Text.Json;

namespace CPE.DapperIdentity.Jwt.Client;

/// <summary>
/// Single source of truth for JWT authentication lifecycle in Blazor WebAssembly.
/// Owns all localStorage reads and writes for <c>authToken</c> and <c>refreshToken</c>,
/// maintains an in-memory cache to eliminate redundant storage reads, and coordinates
/// login, logout, and token refresh operations.
/// </summary>
/// <remarks>
/// <para>
/// Registered as <c>Scoped</c> so the in-memory token cache survives for the full
/// browser-tab lifetime. In Blazor WASM (single user per tab), scoped is effectively
/// a singleton per circuit.
/// </para>
/// <para>
/// No other class should read or write <c>authToken</c>/<c>refreshToken</c> from
/// localStorage directly. <see cref="GetCurrentTokenAsync"/> is the single retrieval
/// point; <see cref="Login"/>, <see cref="Logout"/>, and <see cref="RefreshToken"/>
/// are the only mutation points.
/// </para>
/// <para>
/// <c>HttpClient.DefaultRequestHeaders</c> is intentionally not managed here.
/// Auth header stamping is the sole responsibility of <see cref="HttpInterceptorService"/>,
/// which calls <see cref="GetCurrentTokenAsync"/> through <c>RefreshTokenService</c>.
/// </para>
/// </remarks>
public class JwtWasmClient
{
    private readonly ILocalStorageService _localStorage;
    private readonly JwtAuthClient _jwtAuthClient;

    /// <summary>localStorage key for the JWT access token.</summary>
    private const string AuthTokenKey = "authToken";

    /// <summary>localStorage key for the refresh token.</summary>
    private const string RefreshTokenKey = "refreshToken";

    /// <summary>
    /// In-memory token cache. <see langword="null"/> means cold — not yet read from
    /// localStorage. An empty string means the cache has been read but no token exists
    /// (logged out). This distinction prevents redundant localStorage reads.
    /// </summary>
    private string? _cachedToken;

    /// <summary>
    /// Initializes a new instance of <see cref="JwtWasmClient"/>.
    /// </summary>
    /// <param name="jwtAuthClient">Server-side auth HTTP client (login, refresh, forgot-password endpoints).</param>
    /// <param name="localStorage">Blazor WASM localStorage abstraction for token persistence.</param>
    public JwtWasmClient(JwtAuthClient jwtAuthClient, ILocalStorageService localStorage)
    {
        _jwtAuthClient = jwtAuthClient;
        _localStorage = localStorage;
    }

    /// <summary>
    /// Returns the current valid JWT token, refreshing it proactively if it is within
    /// 2 minutes of expiry. This is the single method <see cref="HttpInterceptorService"/>
    /// calls before stamping every outgoing request.
    /// </summary>
    /// <returns>
    /// The current JWT string if authenticated; <see langword="null"/> if no token exists
    /// (user is logged out or the app has never authenticated).
    /// </returns>
    public async Task<string?> GetValidTokenAsync()
    {
        var token = await GetCurrentTokenAsync();
        if (string.IsNullOrEmpty(token)) return null;

        if (IsTokenExpiringSoon(token))
        {
            var refreshed = await RefreshToken();
            return refreshed.Succeeded ? refreshed.Tokens.Token : null;
        }

        return token;
    }

    /// <summary>
    /// Returns the current JWT auth token. Uses the in-memory cache when warm;
    /// performs a single localStorage read on cold start and caches the result.
    /// </summary>
    /// <returns>
    /// The stored JWT string, or <see langword="null"/> when no token exists
    /// (user is logged out or the app has never authenticated).
    /// </returns>
    public async Task<string?> GetCurrentTokenAsync()
    {
        if (_cachedToken != null) return _cachedToken;
        _cachedToken = await _localStorage.GetItemAsync<string>(AuthTokenKey);
        return _cachedToken;
    }

    /// <summary>
    /// Determines whether the given token is within the specified number of minutes
    /// of expiry. Used by <c>RefreshTokenService</c> to decide whether a
    /// proactive refresh is warranted before the current request.
    /// </summary>
    /// <param name="token">Raw JWT string to inspect.</param>
    /// <param name="withinMinutes">
    /// Refresh threshold in minutes before expiry. Defaults to 2.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the token expires within <paramref name="withinMinutes"/>
    /// minutes; <see langword="false"/> if it is still valid or the token is malformed.
    /// </returns>
    public bool IsTokenExpiringSoon(string token, int withinMinutes = 2)
    {
        try
        {
            var payload = token.Split('.')[1];
            switch (payload.Length % 4)
            {
                case 2: payload += "=="; break;
                case 3: payload += "="; break;
            }
            var jsonBytes = Convert.FromBase64String(payload);
            using var doc = JsonDocument.Parse(jsonBytes);
            var exp = doc.RootElement.GetProperty("exp").GetInt64();
            var expTime = DateTimeOffset.FromUnixTimeSeconds(exp);
            return (expTime - DateTime.UtcNow).TotalMinutes <= withinMinutes;
        }
        catch
        {
            // Malformed token — treat as not expiring and let the request fail naturally.
            return false;
        }
    }

    /// <summary>
    /// Authenticates against the server, persists the resulting tokens to localStorage,
    /// warms the in-memory cache, and invokes the Blazor auth state notification callback.
    /// </summary>
    /// <param name="userForAuthentication">User credentials to authenticate.</param>
    /// <param name="notifyUserAuthentication">
    /// Delegate from <c>AuthStateProvider.NotifyUserAuthentication</c> that updates
    /// Blazor's <see cref="Microsoft.AspNetCore.Components.Authorization.AuthenticationState"/>
    /// after a successful login.
    /// </param>
    /// <returns>
    /// A successful <see cref="AuthResult"/> carrying the tokens, or a failed one naming the
    /// reason. Nothing is written to storage and no notification is raised on failure.
    /// </returns>
    public async Task<AuthResult> Login(AuthRequest userForAuthentication, Action<string> notifyUserAuthentication)
    {
        var result = await _jwtAuthClient.Login(userForAuthentication);
        if (!result.Succeeded) return result;

        await SetTokensAsync(result.Tokens);
        notifyUserAuthentication(result.Tokens.Token);
        return result;
    }

    /// <summary>
    /// Clears all stored tokens from both localStorage and the in-memory cache,
    /// then invokes the Blazor auth state notification callback to transition
    /// the application to the anonymous (unauthenticated) state.
    /// </summary>
    /// <param name="notifyUserLogout">
    /// Delegate from <c>AuthStateProvider.NotifyUserLogout</c> that updates
    /// Blazor's authentication state after logout.
    /// </param>
    public async Task Logout(Action notifyUserLogout)
    {
        await ClearTokensAsync();
        notifyUserLogout();
    }

    /// <summary>
    /// Exchanges the stored refresh token for a new JWT, updates localStorage,
    /// and warms the in-memory cache with the new token.
    /// </summary>
    /// <returns>
    /// A successful <see cref="AuthResult"/> carrying the new tokens, or a failed one naming
    /// the reason.
    /// </returns>
    /// <remarks>
    /// Storage is only touched when the outcome is unambiguous. A rejected refresh token means
    /// the session is genuinely over, so the stored pair is cleared; a server error or an
    /// unreadable reply says nothing about the session, so the existing tokens are left alone to
    /// be retried. The previous version wrote the response's nulls to storage either way, which
    /// turned any transient server hiccup into a silent logout.
    /// </remarks>
    public async Task<AuthResult> RefreshToken()
    {
        var token = await _localStorage.GetItemAsync<string>(AuthTokenKey);
        var refreshToken = await _localStorage.GetItemAsync<string>(RefreshTokenKey);
        var result = await _jwtAuthClient.RefreshToken(new RefreshTokenDto { Token = token, RefreshToken = refreshToken });

        if (result.Succeeded)
        {
            await SetTokensAsync(result.Tokens);
        }
        else if (result.Failure == AuthFailure.InvalidCredentials)
        {
            await ClearTokensAsync();
        }

        return result;
    }

    /// <summary>
    /// Sends a forgot-password request for the specified email address.
    /// </summary>
    /// <param name="userName">Email address of the account to reset.</param>
    /// <returns><see langword="true"/> if the server accepted the request.</returns>
    public async Task<bool> ForgotPassword(string userName)
        => await _jwtAuthClient.ForgotPassword(userName);

    /// <summary>
    /// Resets the user's password using the provided reset code.
    /// </summary>
    /// <param name="userName">Email address of the account.</param>
    /// <param name="password">New password to set.</param>
    /// <param name="code">Reset code delivered to the user (e.g., via email).</param>
    /// <returns><see langword="true"/> if the reset was accepted by the server.</returns>
    public async Task<bool> ResetPassword(string userName, string password, string code)
        => await _jwtAuthClient.ResetPassword(userName, password, code);

    /// <summary>
    /// Persists both tokens to localStorage and updates the in-memory cache.
    /// Called by <see cref="Login"/> and <see cref="RefreshToken"/> after a
    /// successful server response.
    /// </summary>
    private async Task SetTokensAsync(AuthTokens tokens)
    {
        _cachedToken = tokens.Token;
        await _localStorage.SetItemAsync(AuthTokenKey, tokens.Token);
        await _localStorage.SetItemAsync(RefreshTokenKey, tokens.RefreshToken);
    }

    /// <summary>Removes both tokens from localStorage and empties the in-memory cache.</summary>
    private async Task ClearTokensAsync()
    {
        _cachedToken = null;
        await _localStorage.RemoveItemsAsync(new[] { AuthTokenKey, RefreshTokenKey });
    }
}
