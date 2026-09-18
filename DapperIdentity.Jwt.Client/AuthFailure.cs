namespace CPE.DapperIdentity.Jwt.Client;

/// <summary>
/// Why an authentication attempt did not produce tokens.
/// </summary>
/// <remarks>
/// Deliberately coarse. The server does not tell the client whether an account exists, so this
/// enum cannot either; <see cref="InvalidCredentials"/> covers "the server rejected this attempt"
/// without claiming to know which half was wrong.
/// </remarks>
public enum AuthFailure
{
    /// <summary>No failure: the attempt succeeded and tokens are present.</summary>
    None = 0,

    /// <summary>The server rejected the credentials (401, or a 400 it chose to answer with).</summary>
    InvalidCredentials,

    /// <summary>The server answered, but not successfully - a 5xx, or any other unexpected status.</summary>
    ServerError,

    /// <summary>
    /// The server reported success but the body could not be turned into tokens: absent, not JSON,
    /// or JSON carrying no access token.
    /// </summary>
    MalformedResponse,
}
