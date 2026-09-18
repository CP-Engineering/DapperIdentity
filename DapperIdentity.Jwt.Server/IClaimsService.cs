using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityUser = CPE.DapperIdentity.Stores.Models.CustomIdentityUser;

namespace CPE.DapperIdentity.Jwt.Server
{
    /// <summary>
    /// Optional hook for claims the consumer computes rather than stores.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="TokenService"/> takes this as an optional constructor argument. Register an
    /// implementation and its claims are added to every access token alongside the roles and the
    /// claims held in the claim store; leave it unregistered and the step is skipped.
    /// </para>
    /// <para>
    /// The use for it is a claim derived from state that has no row in IdentityUserClaim - a
    /// tenant id read from another table, say, or a flag computed per request.
    /// </para>
    /// </remarks>
    public interface IClaimsService
    {
        /// <summary>Returns the extra claims to write into this user's token.</summary>
        /// <param name="user">The user the token is being issued for.</param>
        /// <returns>
        /// The claims to add. Return an empty sequence rather than null - the caller adds the
        /// result to a list without checking.
        /// </returns>
        Task<IEnumerable<Claim>> ClaimsToAdd(IdentityUser user);
    }

    //public class ClaimsService : IClaimsService
    //{
    //    private DbContext _context;

    //    public ClaimsService(DbContext context)
    //    {
    //        _context = context;
    //    }

    //    public Task AddClaims(Token token)
    //    {
    //        var user = await _context.Users.FindAsync(token.UserId);
    //        if (user.IsAdmin)
    //            token.Claims.Add("IsAdmin", "true");
    //        // add other claims
    //    }
    //}

//    // Manual DI:
//    var claimsService = new ClaimsService(_context);
//    var tokenService = new TokenService(claimsService);

//    // Container DI:
//    services.AddScoped<IClaimsService, ClaimsService>();
//services.AddScoped<ITokenService, TokenService>();
}
