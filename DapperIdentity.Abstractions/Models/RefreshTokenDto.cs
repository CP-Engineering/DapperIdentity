using System.ComponentModel.DataAnnotations;

namespace CPE.DapperIdentity.Abstractions.Models;

/// <summary>
/// The pair a client sends to exchange an expired access token for a new one.
/// </summary>
/// <remarks>
/// Both properties were non-nullable, which with nullable reference types enabled made ASP.NET
/// model binding treat them as implicitly required. They are nullable now to describe what the
/// type can actually hold, and carry explicit <see cref="RequiredAttribute"/> so the binding
/// contract survives the change and is visible in the source rather than emergent from a project
/// setting.
/// </remarks>
public class RefreshTokenDto
{
    /// <summary>The expired (or expiring) access token.</summary>
    [Required]
    public string? Token { get; set; }

    /// <summary>The refresh token issued alongside it.</summary>
    [Required]
    public string? RefreshToken { get; set; }
}
