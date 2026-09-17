using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using CPE.DapperIdentity.Stores;
using CPE.DapperIdentity.Stores.Models;
using DapperRepository;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// Round-trip coverage for the claim half of <see cref="UserStore"/>, against a real database.
/// </summary>
/// <remarks>
/// The DELETE these exercise is plain ANSI SQL with no dialect features, so proving it on SQLite is
/// genuine evidence for MySQL as well. A mock would only have asserted that the store called the
/// statement it was written to call, which for a method whose entire job <em>is</em> the statement
/// proves close to nothing.
/// </remarks>
public sealed class UserStoreClaimTests : IClassFixture<SqliteSchemaFixture>
{
    private readonly SqliteSchemaFixture _fixture;

    public UserStoreClaimTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    private UserStore NewStore() => new(
        _fixture.Services.GetRequiredService<IRepository<CustomIdentityUser>>(),
        _fixture.Services.GetRequiredService<IRepository<CustomIdentityUserClaim>>());

    private async Task<CustomIdentityUser> SeedUserAsync()
    {
        var user = new CustomIdentityUser { UserName = "claims-subject", Email = "claims@example.test" };
        await _fixture.Services.GetRequiredService<IRepository<CustomIdentityUser>>().InsertAsync(user);
        return user;
    }

    [Fact]
    public async Task AddClaimsAsync_then_GetClaimsAsync_returns_what_was_added()
    {
        var store = NewStore();
        var user = await SeedUserAsync();

        await store.AddClaimsAsync(user, new[] { new Claim("scope", "read") }, CancellationToken.None);

        var claims = await store.GetClaimsAsync(user, CancellationToken.None);

        Assert.Single(claims);
        Assert.Equal("scope", claims[0].Type);
        Assert.Equal("read", claims[0].Value);
    }

    /// <summary>
    /// The converse of the test above: this is what proves the suite can actually detect a removal
    /// failing, rather than passing because nothing was there to remove.
    /// </summary>
    [Fact]
    public async Task RemoveClaimsAsync_removes_the_named_claim()
    {
        var store = NewStore();
        var user = await SeedUserAsync();

        await store.AddClaimsAsync(user, new[] { new Claim("scope", "read") }, CancellationToken.None);
        Assert.Single(await store.GetClaimsAsync(user, CancellationToken.None));

        await store.RemoveClaimsAsync(user, new[] { new Claim("scope", "read") }, CancellationToken.None);

        Assert.Empty(await store.GetClaimsAsync(user, CancellationToken.None));
    }

    [Fact]
    public async Task RemoveClaimsAsync_leaves_the_user_s_other_claims_alone()
    {
        var store = NewStore();
        var user = await SeedUserAsync();

        await store.AddClaimsAsync(
            user,
            new[] { new Claim("scope", "read"), new Claim("scope", "write"), new Claim("tenant", "acme") },
            CancellationToken.None);

        await store.RemoveClaimsAsync(user, new[] { new Claim("scope", "read") }, CancellationToken.None);

        var remaining = await store.GetClaimsAsync(user, CancellationToken.None);

        Assert.Equal(2, remaining.Count);
        Assert.DoesNotContain(remaining, c => c.Type == "scope" && c.Value == "read");
        Assert.Contains(remaining, c => c.Type == "scope" && c.Value == "write");
        Assert.Contains(remaining, c => c.Type == "tenant" && c.Value == "acme");
    }

    [Fact]
    public async Task RemoveClaimsAsync_does_not_touch_another_user_s_matching_claim()
    {
        var store = NewStore();
        var mine = await SeedUserAsync();
        var theirs = await SeedUserAsync();

        await store.AddClaimsAsync(mine, new[] { new Claim("scope", "read") }, CancellationToken.None);
        await store.AddClaimsAsync(theirs, new[] { new Claim("scope", "read") }, CancellationToken.None);

        await store.RemoveClaimsAsync(mine, new[] { new Claim("scope", "read") }, CancellationToken.None);

        Assert.Empty(await store.GetClaimsAsync(mine, CancellationToken.None));
        Assert.Single(await store.GetClaimsAsync(theirs, CancellationToken.None));
    }
}
