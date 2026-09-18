using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using System.Threading;

using Dapper.Contrib.Extensions;
using Dapper;
using DapperRepository;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;
using IdentityRole = CPE.DapperIdentity.Stores.Models.CustomIdentityRole;
using IdentityUserClaim = CPE.DapperIdentity.Stores.Models.CustomIdentityUserClaim;
using System.Security.Claims;
using CPE.DapperIdentity.Stores.Models;


namespace CPE.DapperIdentity.Stores
{
    /// <summary>
    /// Dapper-backed ASP.NET Core Identity user store.
    /// </summary>
    /// <remarks>
    /// Implements the nine store interfaces listed below, but not all of them completely: the
    /// login (external-provider) members and most of the role members throw, because there is no
    /// IdentityUserLogin or IdentityUserRole table behind them. Each such member says so on itself.
    /// </remarks>
    public class UserStore : IUserStore<IdentityUser>,
                             IUserEmailStore<IdentityUser>,
                             IUserLoginStore<IdentityUser>,
                             IUserPasswordStore<IdentityUser>,
                             IUserPhoneNumberStore<IdentityUser>,
                             IUserRoleStore<IdentityUser>,
                             IQueryableUserStore<IdentityUser>,
                             IUserSecurityStampStore<IdentityUser>,
                             IUserClaimStore<IdentityUser>
                             //IUserTwoFactorStore<>,
                             //IUserLockoutStore<>
                            
    {
        private IRepository<IdentityUser> _IdentityUserRepository;
        private IRepository<IdentityUserClaim> _IdentityUserClaimRepository;

        //public UserStore(IRepository<IdentityUser> userRepository)
        //{
            
        //}
        /// <summary>Creates the store over the user and claim repositories.</summary>
        /// <param name="userRepository">Repository bound to the IdentityUser table.</param>
        /// <param name="claimRepository">Repository bound to the IdentityUserClaim table.</param>
        public UserStore(IRepository<IdentityUser> userRepository, IRepository<IdentityUserClaim> claimRepository)
        {
            _IdentityUserRepository = userRepository;
            _IdentityUserClaimRepository = claimRepository;
        }

        IQueryable<IdentityUser> IQueryableUserStore<IdentityUser>.Users => this.GetUsers().Result; //repository.FindAllAsync().Result.AsQueryable();

        /// <summary>
        /// Loads every user with their roles attached, backing the IQueryableUserStore.Users
        /// property.
        /// </summary>
        /// <remarks>
        /// The join is wrong and the result should not be trusted: it matches IdentityRole on the
        /// USER's id (<c>ON U.Id = R.Id</c>), which only finds a role whose primary key happens to
        /// equal a user's. There is no IdentityUserRole table to join through, which is the real
        /// problem - see What's Next 1.011. Every user is also materialised in one pass, so this
        /// scales with the whole table.
        /// </remarks>
        /// <returns>All users, each with a Roles collection populated by the join above.</returns>
        private async Task<IQueryable<IdentityUser>> GetUsers()
        {
            var userDictionary = new Dictionary<string, IdentityUser>();

            using (var connection = _IdentityUserRepository.DbConnection)
            {
                var sql = @"SELECT * FROM IdentityUser as U LEFT JOIN IdentityRole as R ON U.Id=R.Id";
                var list = await connection.QueryAsync<IdentityUser, IdentityRole, IdentityUser>(
                    sql,
                    (user, role) =>
                    {
                        //IdentityUser user;

                        if (!userDictionary.TryGetValue(user.Id, out var foundUser))
                        {
                            foundUser = user;
                            foundUser.Roles = new List<IdentityRole>();
                            userDictionary.Add(user.Id, foundUser);
                        }
                        foundUser.Roles.Add(role);
                        return foundUser;
                    },
                    splitOn: "Id");

                //.ToList();
                return list.Distinct().AsQueryable();
            }
        }

        /// <summary>Not implemented. External logins need an IdentityUserLogin table, which this library has no model or schema for.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="login">The external login to associate.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Inserts the user, assigning an Id when the caller did not supply one.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (user.Id is null)
            {
                user.Id = Guid.NewGuid().ToString();
            }
            var something = await _IdentityUserRepository.InsertAsync(user); // InsertAsync(user);
            
            return IdentityResult.Success;
        }

        //using (var connection = new SqlConnection(_connectionString))
        //{
        //    await connection.OpenAsync(cancellationToken);
        //    user.Id = await connection.QuerySingleAsync<int>($@"INSERT INTO [IdentityUser] ([UserName], [NormalizedUserName], [Email],
        //        [NormalizedEmail], [EmailConfirmed], [PasswordHash], [PhoneNumber], [PhoneNumberConfirmed], [TwoFactorEnabled])
        //        VALUES (@{nameof(IdentityUser.UserName)}, @{nameof(IdentityUser.NormalizedUserName)}, @{nameof(IdentityUser.Email)},
        //        @{nameof(IdentityUser.NormalizedEmail)}, @{nameof(IdentityUser.EmailConfirmed)}, @{nameof(IdentityUser.PasswordHash)},
        //        @{nameof(IdentityUser.PhoneNumber)}, @{nameof(IdentityUser.PhoneNumberConfirmed)}, @{nameof(IdentityUser.TwoFactorEnabled)});
        //        SELECT CAST(SCOPE_IDENTITY() as int)", user);
        //}


        /// <summary>Deletes the user row. Claims are not cascaded and are left behind.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            await _IdentityUserRepository.DeleteAsync(user);
            return IdentityResult.Success;

        }

        /// <summary>Nothing is held open per store instance.</summary>
        public void Dispose()
        {
            //nothing to dispose
            //throw new NotImplementedException();
        }

        /// <summary>Finds a user by normalized email address.</summary>
        /// <param name="normalizedEmail">The upper-cased email to match.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user, or null when no row matches.</returns>
        public async Task<IdentityUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            
            var dynamicParams = new DynamicParameters();
            dynamicParams.Add("NormalizedEmail", normalizedEmail, System.Data.DbType.String);
            string sql = @"SELECT * FROM IdentityUser WHERE NormalizedEmail = @NormalizedEmail";
                        return await _IdentityUserRepository.SelectFirstOrDefaultAsync(sql, dynamicParams);
        }

        /// <summary>Finds a user by primary key.</summary>
        /// <param name="userId">The user Id.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user, or null when no row matches.</returns>
        public async Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            return await _IdentityUserRepository.FindByIDAsync(userId);
        }

        /// <summary>Not implemented. External logins need an IdentityUserLogin table, which this library has no model or schema for.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="loginProvider">The external provider name.</param>
        /// <param name="providerKey">The provider's key for the user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<IdentityUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Finds a user by normalized user name.</summary>
        /// <param name="normalizedUserName">The upper-cased user name to match.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user, or null when no row matches.</returns>
        public async Task<IdentityUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IdentityUser? foundUser;
            using (var conn = _IdentityUserRepository.DbConnection)
            { 
                var dynamicParams = new DynamicParameters();
                dynamicParams.Add("UserName", normalizedUserName, System.Data.DbType.String);
                foundUser = await conn.QueryFirstOrDefaultAsync<IdentityUser>("SELECT * FROM IdentityUser WHERE NormalizedUserName = @UserName", dynamicParams);
            }
            return foundUser;            
        }

        /// <summary>Returns the user's email address.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The email, or null when the row has none.</returns>
        public Task<string?> GetEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        /// <summary>Returns whether the email address has been confirmed.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>True when confirmed.</returns>
        public Task<bool> GetEmailConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<bool>(user.EmailConfirmed);
            //throw new NotImplementedException();
        }

        /// <summary>Not implemented. External logins need an IdentityUserLogin table, which this library has no model or schema for.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Not implemented. Read the NormalizedEmail property directly; the column exists, this accessor was never written.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<string?> GetNormalizedEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Not implemented. Read the NormalizedUserName property directly; the column exists, this accessor was never written.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<string?> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Returns the stored password hash.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The hash, or null when the account has no password set.</returns>
        public Task<string?> GetPasswordHashAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.PasswordHash);
        }

        /// <summary>Returns the user's phone number.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The number, or null when the row has none.</returns>
        public Task<string?> GetPhoneNumberAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.PhoneNumber);
            //throw new NotImplementedException();
        }

        /// <summary>Not implemented. The PhoneNumberConfirmed column exists and is mapped; only this accessor is missing.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Returns the user's primary key.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user Id.</returns>
        /// <exception cref="InvalidOperationException">The user has no Id, so it was never persisted.</exception>
        public Task<string> GetUserIdAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            // The store contract promises a non-null id, so a user that has none
            // never came from the database and cannot be identified.
            return Task.FromResult(user.Id ?? throw new InvalidOperationException(
                "The user has no Id; it was never persisted."));
            //throw new NotImplementedException();
        }


        /// <summary>Returns the user's login name.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user name, or null when the row has none.</returns>
        public Task<string?> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.UserName);
            //throw new NotImplementedException();
        }

        /// <summary>Returns whether the account has a password set.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>True when a password hash is stored.</returns>
        public Task<bool> HasPasswordAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<bool>(user.PasswordHash != null);
        }

        /// <summary>Not implemented. External logins need an IdentityUserLogin table, which this library has no model or schema for.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The external provider name.</param>
        /// <param name="providerKey">The provider's key for the user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Sets the email address in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="email">The new address.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetEmailAsync(IdentityUser user, string? email, CancellationToken cancellationToken)
        {
            user.Email = email;
            return Task.FromResult(0);
        }

        /// <summary>Sets the email-confirmed flag in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="confirmed">Whether the address is confirmed.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        /// <summary>Sets the normalized email in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="normalizedEmail">The upper-cased address.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetNormalizedEmailAsync(IdentityUser user, string? normalizedEmail, CancellationToken cancellationToken)
        {
            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        /// <summary>Sets the normalized user name in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="normalizedName">The upper-cased user name.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetNormalizedUserNameAsync(IdentityUser user, string? normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.FromResult(0);
        }

        /// <summary>Sets the password hash in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="passwordHash">The hash to store. Never a plain password.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetPasswordHashAsync(IdentityUser user, string? passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
            //throw new NotImplementedException();
        }

        /// <summary>Sets the phone number in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="phoneNumber">The new number.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetPhoneNumberAsync(IdentityUser user, string? phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        /// <summary>Not implemented. The PhoneNumberConfirmed column exists and is mapped; only this accessor is missing.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="confirmed">Whether the number is confirmed.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>Sets the login name in memory; call UpdateAsync to persist it.</summary>
        /// <param name="user">The user.</param>
        /// <param name="userName">The new user name.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        public Task SetUserNameAsync(IdentityUser user, string? userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.FromResult(0);
        }

        /// <summary>Persists changes to an existing user.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>Always <see cref="IdentityResult.Success"/>; failures surface as exceptions.</returns>
        public async Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await _IdentityUserRepository.UpdateAsync(user);
            return IdentityResult.Success;
        }

        Task IUserRoleStore<IdentityUser>.AddToRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        async Task<IList<string>> IUserRoleStore<IdentityUser>.GetRolesAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            string sql = "SELECT Name FROM IdentityRole WHERE id = @id";
            var dynamicParams = new DynamicParameters();
            dynamicParams.Add("id", user.Id, System.Data.DbType.String);
            var result = await _IdentityUserRepository.DbConnection.QueryAsync<string>(sql, dynamicParams);
            return result.ToList<string>();
        }

        Task<IList<IdentityUser>> IUserRoleStore<IdentityUser>.GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task<bool> IUserRoleStore<IdentityUser>.IsInRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        Task IUserRoleStore<IdentityUser>.RemoveFromRoleAsync(IdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Sets the security stamp in memory; call UpdateAsync to persist it.
        /// </summary>
        /// <remarks>
        /// The stamp changes whenever credentials change, which is how tokens issued before the
        /// change stop being accepted. Setting it without persisting leaves those tokens valid.
        /// </remarks>
        /// <param name="user">The user.</param>
        /// <param name="stamp">The new stamp.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A completed task.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="user"/> is null.</exception>
        public Task SetSecurityStampAsync(IdentityUser user, string stamp, CancellationToken cancellationToken)
        {
            //ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.SecurityStamp = stamp;
            //UpdateAsync(user, cancellationToken);
            return Task.FromResult(0);
        }
        
        /// <summary>
        /// Returns the user's security stamp.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The stamp, or null when the row has none.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="user"/> is null.</exception>
        public Task<string?> GetSecurityStampAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            //ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.SecurityStamp);
        }

        #region User Claims Region
        /// <summary>Returns every claim stored against the user.</summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>The user's claims; empty when it has none.</returns>
        public async Task<IList<Claim>> GetClaimsAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sql = "SELECT * from IdentityUserClaim Where UserId = @userId";
            
            var dynamicParams = new DynamicParameters();
            dynamicParams.Add("@userId", user.Id);
            
            var result = (await _IdentityUserRepository.DbConnection.QueryAsync<IdentityUserClaim>(sql, dynamicParams)).ToList();
            
            var claims = new List<Claim>();
            
            result.ForEach(x => claims.Add(x.ToClaim()));
            return claims;
        }

        /// <summary>Stores the given claims against the user.</summary>
        /// <remarks>No de-duplication: adding a claim the user already holds inserts a second row.</remarks>
        /// <param name="user">The user.</param>
        /// <param name="claims">The claims to add.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AddClaimsAsync(CustomIdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var idClaims = new List<IdentityUserClaim>();
            foreach (var claim in claims)
            {
                var idc = new IdentityUserClaim(){ Id = Guid.NewGuid().ToString(), UserId = user.Id,  ClaimType = claim.Type, ClaimValue = claim.Value };
                idClaims.Add(idc);
            }
            await _IdentityUserClaimRepository.InsertAsync(idClaims);

        }

        /// <summary>Not implemented. Call RemoveClaimsAsync then AddClaimsAsync; note that is two statements, not one transaction.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="user">The user.</param>
        /// <param name="claim">The claim to replace.</param>
        /// <param name="newClaim">The claim to replace it with.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task ReplaceClaimAsync(CustomIdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Deletes the named claims from the user, matching on type and value.
        /// </summary>
        /// <remarks>
        /// Implemented 2026-09-17. Until then the body built the statement and its parameters and
        /// then returned without executing anything, so removing a claim reported success and
        /// changed nothing. The half-written parameters were also wrong: @claimValue was never
        /// supplied and @claimType was bound to the whole claim collection rather than a type.
        ///
        /// One execution per claim, via Dapper's multi-exec: the statement matches a single
        /// claim, and the method takes a collection. Matching on UserId as well as type and value
        /// is what stops one user's removal touching another user's identical claim.
        /// </remarks>
        public async Task RemoveClaimsAsync(CustomIdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var parameters = claims.Select(claim => new
            {
                userId = user.Id,
                claimType = claim.Type,
                claimValue = claim.Value
            }).ToArray();

            // Dapper treats an empty collection as nothing to do, but being explicit keeps a
            // needless connection from being opened.
            if (parameters.Length == 0) return;

            var sql = @"DELETE FROM IdentityUserClaim WHERE UserId = @userId AND ClaimType = @claimType AND ClaimValue = @claimValue";

            using (var connection = _IdentityUserClaimRepository.DbConnection)
            {
                await connection.ExecuteAsync(sql, parameters);
            }
        }

        /// <summary>Not implemented. Would need a join from IdentityUserClaim back to IdentityUser, which nothing calls today.</summary>
        /// <exception cref="NotImplementedException">Always.</exception>
        /// <param name="claim">The claim to search for.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public Task<IList<CustomIdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
