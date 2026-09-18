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
        public UserStore(IRepository<IdentityUser> userRepository, IRepository<IdentityUserClaim> claimRepository)
        {
            _IdentityUserRepository = userRepository;
            _IdentityUserClaimRepository = claimRepository;
        }

        IQueryable<IdentityUser> IQueryableUserStore<IdentityUser>.Users => this.GetUsers().Result; //repository.FindAllAsync().Result.AsQueryable();

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

        public Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

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


        public async Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            await _IdentityUserRepository.DeleteAsync(user);
            return IdentityResult.Success;

        }

        public void Dispose()
        {
            //nothing to dispose
            //throw new NotImplementedException();
        }

        public async Task<IdentityUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            
            var dynamicParams = new DynamicParameters();
            dynamicParams.Add("NormalizedEmail", normalizedEmail, System.Data.DbType.String);
            string sql = @"SELECT * FROM IdentityUser WHERE NormalizedEmail = @NormalizedEmail";
                        return await _IdentityUserRepository.SelectFirstOrDefaultAsync(sql, dynamicParams);
        }

        public async Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            return await _IdentityUserRepository.FindByIDAsync(userId);
        }

        public Task<IdentityUser?> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

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

        public Task<string?> GetEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<bool>(user.EmailConfirmed);
            //throw new NotImplementedException();
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetNormalizedEmailAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string?> GetPasswordHashAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.PasswordHash);
        }

        public Task<string?> GetPhoneNumberAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.PhoneNumber);
            //throw new NotImplementedException();
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetUserIdAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            // The store contract promises a non-null id, so a user that has none
            // never came from the database and cannot be identified.
            return Task.FromResult(user.Id ?? throw new InvalidOperationException(
                "The user has no Id; it was never persisted."));
            //throw new NotImplementedException();
        }


        public Task<string?> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<string?>(user.UserName);
            //throw new NotImplementedException();
        }

        public Task<bool> HasPasswordAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult<bool>(user.PasswordHash != null);
        }

        public Task RemoveLoginAsync(IdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetEmailAsync(IdentityUser user, string? email, CancellationToken cancellationToken)
        {
            user.Email = email;
            return Task.FromResult(0);
        }

        public Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task SetNormalizedEmailAsync(IdentityUser user, string? normalizedEmail, CancellationToken cancellationToken)
        {
            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        public Task SetNormalizedUserNameAsync(IdentityUser user, string? normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.FromResult(0);
        }

        public Task SetPasswordHashAsync(IdentityUser user, string? passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
            //throw new NotImplementedException();
        }

        public Task SetPhoneNumberAsync(IdentityUser user, string? phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetUserNameAsync(IdentityUser user, string? userName, CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.FromResult(0);
        }

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
        ///     Set the security stamp for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="stamp"></param>
        /// <returns></returns>
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
        ///     Get the security stamp for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
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

        public Task<IList<CustomIdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }
        #endregion
    }
}
