using System.ComponentModel.DataAnnotations;

namespace CPE.DapperIdentity.Abstractions.Models
{
    /// <summary>
    /// The body a client posts to start a password reset.
    /// </summary>
    public class ForgotPasswordRequest
    {
        /// <summary>
        /// The address to send the reset link to. The server answers 200 whether or not an account
        /// exists for it, so a caller cannot use this endpoint to discover which addresses are
        /// registered.
        /// </summary>
        [Required]
        public string? Email { get; set; }
    }
}
