using Dapper.Contrib.Extensions;

namespace CPE.DapperIdentity.Stores.Models
{
    /// <summary>The Dapper-mapped role row.</summary>
    [Table("IdentityRole")]
    public class CustomIdentityRole
    {
        /// <summary>Primary key.</summary>
        [ExplicitKey]
        public string? Id { get; set; }

        /// <summary>The role name, as used in authorization checks.</summary>
        public string? Name { get; set; }

        /// <summary>Free text describing what the role is for.</summary>
        public string? Description { get; set; }
    }
}
