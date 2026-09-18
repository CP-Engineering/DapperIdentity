namespace CPE.DapperIdentity.Jwt.Client;

/// <summary>
/// The tokens and identity details from a successful authentication.
/// </summary>
/// <remarks>
/// This type only exists when authentication succeeded, which is why <see cref="Token"/> is
/// non-nullable here while its counterpart on the wire model is not: the wire model has to
/// describe failure too, this one does not. Construct it through
/// <see cref="AuthResult.Success(AuthTokens)"/> rather than handing it round on its own.
/// </remarks>
public sealed class AuthTokens
{
    /// <summary>Creates a token set. Callers come from the client's response mapping.</summary>
    /// <param name="token">The JWT access token; never null or blank.</param>
    /// <param name="refreshToken">The refresh token, when the server issued one.</param>
    /// <param name="username">The authenticated user's name, when the server returned it.</param>
    /// <param name="email">The authenticated user's email, when the server returned it.</param>
    public AuthTokens(string token, string? refreshToken, string? username, string? email)
    {
        Token = token;
        RefreshToken = refreshToken;
        Username = username;
        Email = email;
    }

    /// <summary>The JWT access token. Its presence is what makes the attempt a success.</summary>
    public string Token { get; }

    /// <summary>
    /// The refresh token, or null when the server issued none. Null is a degraded but
    /// authenticated state: the session works until the access token expires and cannot be renewed.
    /// </summary>
    public string? RefreshToken { get; }

    /// <summary>The authenticated user's name, when the server returned it.</summary>
    public string? Username { get; }

    /// <summary>The authenticated user's email address, when the server returned it.</summary>
    public string? Email { get; }
}
