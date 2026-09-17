namespace CPE.DapperIdentity.Abstractions.Models;

/// <summary>
/// The body the server returns from a successful login or token refresh.
/// </summary>
/// <remarks>
/// Every property is nullable because every property genuinely can be absent. The server builds
/// this from columns declared NULL in the schema, and the client returns an empty instance to
/// signal failure - so a non-nullable property here would be a claim the type cannot keep.
/// <c>required</c> would not help: System.Text.Json is satisfied by a field that is present and
/// null, so it checks presence rather than nullness.
/// </remarks>
public class AuthResponse
{
    /// <summary>The authenticated user's name, as stored.</summary>
    public string? Username { get; set; }

    /// <summary>The authenticated user's email address.</summary>
    public string? Email { get; set; }

    /// <summary>The JWT access token. An absent or empty value is how failure reaches the caller.</summary>
    public string? Token { get; set; }

    /// <summary>The refresh token to exchange once <see cref="Token"/> expires.</summary>
    public string? RefreshToken { get; set; }
}
