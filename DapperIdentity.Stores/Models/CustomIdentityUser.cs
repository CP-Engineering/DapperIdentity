using CPE.DapperIdentity.Abstractions;
using System;
using System.Collections.Generic;
using Dapper.Contrib.Extensions;

namespace CPE.DapperIdentity.Stores.Models
{
    /// <summary>
    /// The Dapper-mapped user row. Table and key are declared by attribute, and every public
    /// read/write property not marked <see cref="WriteAttribute"/> false is a column.
    /// </summary>
    /// <remarks>
    /// String members are nullable to match the schema, where every column is declared NULL. The
    /// <c>SchemaMatchesModelsTests</c> suite pins this type against the shipped creation script, so
    /// adding a property here without adding the column is now a failing test rather than a runtime
    /// surprise.
    /// </remarks>
    [Table("IdentityUser")]
    public class CustomIdentityUser : ICustomIdentityUser
    {
        /// <inheritdoc />
        [ExplicitKey]
        public string? Id { get; set; }

        /// <inheritdoc />
        public string? UserName { get; set; }

        /// <inheritdoc />
        public string? NormalizedUserName { get; set; }

        /// <inheritdoc />
        public string? Email { get; set; }

        /// <inheritdoc />
        public string? NormalizedEmail { get; set; }

        /// <inheritdoc />
        public bool EmailConfirmed { get; set; }

        /// <inheritdoc />
        public string? PasswordHash { get; set; }

        /// <inheritdoc />
        public string? PhoneNumber { get; set; }

        /// <inheritdoc />
        public bool PhoneNumberConfirmed { get; set; }

        /// <inheritdoc />
        public bool TwoFactorEnabled { get; set; }

        /// <inheritdoc />
        public string? FirstName { get; set; }

        /// <inheritdoc />
        public string? LastName { get; set; }

        /// <inheritdoc />
        public string? SecurityStamp { get; set; }

        /// <inheritdoc />
        public bool IsEnabled { get; set; }

        /// <inheritdoc />
        public string? RefreshToken { get; set; }

        /// <inheritdoc />
        public DateTime RefreshTokenExpireTime { get; set; }

        /// <summary>
        /// Assigns a new <see cref="Id"/> and <see cref="SecurityStamp"/>, so a user constructed in
        /// code is insertable without the caller remembering to set either.
        /// </summary>
        public CustomIdentityUser()
        {
            Id = Guid.NewGuid().ToString();
            SecurityStamp = Guid.NewGuid().ToString();
        }

        /// <summary>The user's roles. Not a column; populated by a separate query.</summary>
        [Write(false)]
        public List<CustomIdentityRole>? Roles { get; set; }

        /// <summary>
        /// Used in UI to Hide/Show Roles in expansion panel for each user. Not a column.
        /// </summary>
        [Write(false)]
        public bool ShowRoles { get; set; } = false;
    }
}
