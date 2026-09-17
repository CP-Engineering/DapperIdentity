using Dapper.Contrib.Extensions;
using System.Security.Claims;

namespace CPE.DapperIdentity.Stores.Models
{
    /// <summary>The Dapper-mapped user-claim row.</summary>
    [Table("IdentityUserClaim")]
    public class CustomIdentityUserClaim
    {
        /// <summary>Primary key.</summary>
        [ExplicitKey]
        public string? Id { get; set; }

        /// <summary>The user this claim belongs to.</summary>
        public string? UserId { get; set; }

        /// <summary>The claim type, for example a role or scope name.</summary>
        public string? ClaimType { get; set; }

        /// <summary>The claim value.</summary>
        public string? ClaimValue { get; set; }

        /// <summary>Projects this row into the framework's claim type.</summary>
        public Claim ToClaim() => new Claim(ClaimType ?? string.Empty, ClaimValue ?? string.Empty);

        /// <summary>Copies type and value from a framework claim onto this row.</summary>
        public void InitializeFromClaim(Claim claim)
        {
            ClaimType = claim.Type;
            ClaimValue = claim.Value;
        }
    }
}
