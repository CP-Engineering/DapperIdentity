using System;
using Microsoft.AspNetCore.Identity;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using DapperRepository;
using IdentityRole = CPE.DapperIdentity.Stores.Models.CustomIdentityRole;


namespace CPE.DapperIdentity.Stores
{
    /// <summary>
    /// Dapper-backed <see cref="IRoleStore{TRole}"/> over the IdentityRole table.
    /// </summary>
    /// <remarks>
    /// The table has no NormalizedName column, so the normalized name is derived from
    /// <see cref="IdentityRole.Name"/> rather than stored. That keeps existing databases working
    /// without a migration, at two costs worth knowing about: a custom
    /// <see cref="ILookupNormalizer"/> is not honoured here, and name lookups scan rather than seek
    /// because UPPER(Name) cannot use an index. Storing the column properly is tracked for a
    /// later version.
    /// </remarks>
    public class RoleStore : IRoleStore<IdentityRole>, IQueryableRoleStore<IdentityRole>
    {
        private IRepository<IdentityRole> repository;

        /// <summary>Creates the store over the supplied role repository.</summary>
        /// <param name="roleRepository">Repository bound to the IdentityRole table.</param>
        public RoleStore(IRepository<IdentityRole> roleRepository)
        {
            repository = roleRepository;
        }

        /// <summary>All roles, materialised eagerly because the interface is synchronous.</summary>
        public IQueryable<IdentityRole> Roles => repository.FindAllAsync().Result.AsQueryable();

        /// <summary>Inserts the role, assigning an Id when the caller did not supply one.</summary>
        /// <param name="role">The role to persist.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // Id is an ExplicitKey, so the database will not generate one for us.
            if (role.Id is null)
            {
                role.Id = Guid.NewGuid().ToString();
            }
            await repository.InsertAsync(role);
            return IdentityResult.Success;
        }

        /// <summary>Deletes the role.</summary>
        /// <param name="role">The role to delete.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await repository.DeleteAsync(role);
            return IdentityResult.Success;
        }

        /// <summary>Nothing is held open per store instance.</summary>
        public void Dispose()
        {
        }

        /// <summary>Finds a role by its primary key.</summary>
        /// <param name="roleId">The role Id.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The role, or null when no row matches.</returns>
        public async Task<IdentityRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return await repository.FindByIDAsync(roleId);
        }

        /// <summary>Finds a role by its normalized name.</summary>
        /// <param name="normalizedRoleName">The upper-cased role name.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The role, or null when no row matches.</returns>
        /// <remarks>
        /// Compares UPPER(Name) because there is no stored NormalizedName. SQLite's UPPER only
        /// folds ASCII, which is fine for role names but would not be for arbitrary user input.
        /// </remarks>
        public async Task<IdentityRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dynamicParams = new DynamicParameters();
            dynamicParams.Add("NormalizedRoleName", normalizedRoleName, System.Data.DbType.String);
            var sql = @"SELECT * FROM IdentityRole WHERE UPPER(Name) = @NormalizedRoleName";
            return await repository.SelectFirstOrDefaultAsync(sql, dynamicParams);
        }

        /// <summary>Returns the normalized name, derived from <see cref="IdentityRole.Name"/>.</summary>
        /// <param name="role">The role.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The upper-cased name, or null when the role has none.</returns>
        public Task<string?> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(role.Name?.ToUpperInvariant());
        }

        /// <summary>Returns the role's primary key.</summary>
        /// <param name="role">The role.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The role Id.</returns>
        /// <exception cref="InvalidOperationException">The role has no Id, so it was never persisted.</exception>
        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // The store contract promises a non-null id; a role without one never came from the database.
            return Task.FromResult(role.Id ?? throw new InvalidOperationException(
                "The role has no Id; it was never persisted."));
        }

        /// <summary>Returns the role's name.</summary>
        /// <param name="role">The role.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The name, or null when the role has none.</returns>
        public Task<string?> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(role.Name);
        }

        /// <summary>
        /// Deliberately does nothing: the normalized name is derived from
        /// <see cref="IdentityRole.Name"/> on read, so there is nothing to store.
        /// </summary>
        /// <param name="role">The role.</param>
        /// <param name="normalizedName">Ignored.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetNormalizedRoleNameAsync(IdentityRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }

        /// <summary>Sets the role's name in memory; call UpdateAsync to persist it.</summary>
        /// <param name="role">The role.</param>
        /// <param name="roleName">The new name.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetRoleNameAsync(IdentityRole role, string? roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <summary>Persists changes to an existing role.</summary>
        /// <param name="role">The role to update.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await repository.UpdateAsync(role);
            return IdentityResult.Success;
        }
    }
}
