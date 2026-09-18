namespace CPE.DapperIdentity.Abstractions.Models;

/// <summary>
/// The credentials a client posts to the login endpoint.
/// </summary>
public class AuthRequest
{
    /// <summary>The account's email address, which is also its login name.</summary>
    public string? Email { get; set; }

    /// <summary>
    /// The account's password. Travels as plain text in the request body, so the endpoint that
    /// accepts this must only be exposed over HTTPS.
    /// </summary>
    public string? Password { get; set; }
}
