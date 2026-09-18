using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace CPE.DapperIdentity.Abstractions.Models;

/// <summary>
/// The body a client posts to register a new account.
/// </summary>
public class RegistrationRequest
{
    /// <summary>
    /// The new account's email address. Also where the confirmation link is sent, so a typo here
    /// produces an account that can never complete registration.
    /// </summary>
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    /// <summary>The new account's login name.</summary>
    [Required]
    public string? Username { get; set; }

    /// <summary>
    /// The password to set. Travels as plain text in the request body, so the endpoint that
    /// accepts this must only be exposed over HTTPS.
    /// </summary>
    [Required]
    public string? Password { get; set; }

    // Nullable, and deliberately without [Required]: the three properties above carry the attribute
    // explicitly, so the author's intent is that these two are optional. They were non-nullable,
    // which made model binding require them implicitly - the opposite of that intent.

    /// <summary>Given name. Optional.</summary>
    public string? FirstName { get; set; }

    /// <summary>Family name. Optional.</summary>
    public string? LastName { get; set; }

    /// <summary>
    /// User's Id. If none is supplied, one will be created and returned
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Claims to attach to the new user, keyed by claim type. Each entry becomes one
    /// <see cref="System.Security.Claims.Claim"/> on the account as it is created.
    /// </summary>
    /// <remarks>
    /// Being a dictionary, this holds one value per claim type - a user who needs two values for
    /// the same type (two roles, say) cannot be expressed here and has to be given the second
    /// through the claim store afterwards.
    /// </remarks>
    public Dictionary<string, string> Claims { get; set; } = new Dictionary<string, string>();
}
