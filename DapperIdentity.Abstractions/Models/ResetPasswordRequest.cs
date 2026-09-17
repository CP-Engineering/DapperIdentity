using System.ComponentModel.DataAnnotations;

namespace CPE.DapperIdentity.Abstractions.Models;

/// <summary>
/// The body a client posts to complete a password reset.
/// </summary>
/// <remarks>
/// <c>ConfirmPassword</c> and <c>Code</c> were non-nullable without an explicit
/// <see cref="RequiredAttribute"/>, which with nullable reference types enabled made model binding
/// require them anyway. Making them nullable without the attribute would have silently relaxed
/// that - and <c>Code</c> is the reset token, so a request that binds without one has no business
/// reaching the handler. The attributes are explicit now, and the requirement no longer depends on
/// a project-level setting.
/// </remarks>
public class ResetPasswordRequest
{
    /// <summary>The account's email address.</summary>
    [Required]
    [EmailAddress]
    public string? Email { get; set; }

    /// <summary>The new password.</summary>
    [Required]
    [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
    [DataType(DataType.Password)]
    public string? Password { get; set; }

    /// <summary>The new password again; must match <see cref="Password"/>.</summary>
    [Required]
    [DataType(DataType.Password)]
    [Display(Name = "Confirm password")]
    [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
    public string? ConfirmPassword { get; set; }

    /// <summary>The single-use reset token issued by the forgot-password flow.</summary>
    [Required]
    public string? Code { get; set; }
}
