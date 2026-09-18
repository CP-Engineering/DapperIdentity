using System;
using System.Threading;
using System.Threading.Tasks;
using CPE.DapperIdentity.Stores;
using CPE.DapperIdentity.Stores.Models;
using DapperRepository;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// Round-trip coverage for the lookup and lifecycle half of <see cref="UserStore"/>.
/// </summary>
/// <remarks>
/// These are the members a consumer exercises on every sign-in, and all of their signatures
/// changed when the store's nullability was brought in line with the Identity interfaces
/// (Session 33l). Nothing covered them until now - the existing tests reach only the claim
/// members - so a widened return that had quietly stopped finding rows would have gone unnoticed.
/// </remarks>
public sealed class UserStoreTests : IClassFixture<SqliteSchemaFixture>
{
    private readonly SqliteSchemaFixture _fixture;

    public UserStoreTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    private UserStore NewStore() => new(
        _fixture.Services.GetRequiredService<IRepository<CustomIdentityUser>>(),
        _fixture.Services.GetRequiredService<IRepository<CustomIdentityUserClaim>>());

    /// <summary>
    /// Builds a user the way Identity does: the normalized columns are what the lookups match on,
    /// so a fixture that left them unset would pass tests the real flow would fail.
    /// </summary>
    private static CustomIdentityUser User(string name, string email) => new()
    {
        UserName = name,
        NormalizedUserName = name.ToUpperInvariant(),
        Email = email,
        NormalizedEmail = email.ToUpperInvariant(),
        IsEnabled = true
    };

    [Fact]
    public async Task CreateAsync_then_FindByIdAsync_round_trips_the_user()
    {
        var store = NewStore();
        var user = User("round.trip", "round.trip@example.test");

        await store.CreateAsync(user, CancellationToken.None);
        var found = await store.FindByIdAsync(user.Id!, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal("round.trip", found!.UserName);
        Assert.Equal("round.trip@example.test", found.Email);
    }

    [Fact]
    public void The_model_supplies_its_own_Id_so_CreateAsync_never_has_to()
    {
        // CustomIdentityUser's constructor fills Id and SecurityStamp, which is why the guard in
        // CreateAsync is unreachable for a freshly constructed user. Documented rather than
        // assumed, because CustomIdentityRole behaves the opposite way.
        var user = new CustomIdentityUser();

        Assert.False(string.IsNullOrWhiteSpace(user.Id));
        Assert.False(string.IsNullOrWhiteSpace(user.SecurityStamp));
    }

    [Fact]
    public async Task FindByIdAsync_returns_null_for_an_unknown_id()
    {
        var store = NewStore();

        Assert.Null(await store.FindByIdAsync(Guid.NewGuid().ToString(), CancellationToken.None));
    }

    [Fact]
    public async Task FindByNameAsync_matches_on_the_normalized_user_name()
    {
        var store = NewStore();
        var user = User("Sign.In", "sign.in@example.test");
        await store.CreateAsync(user, CancellationToken.None);

        var found = await store.FindByNameAsync("SIGN.IN", CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(user.Id, found!.Id);
    }

    [Fact]
    public async Task FindByNameAsync_returns_null_when_nobody_matches()
    {
        var store = NewStore();

        Assert.Null(await store.FindByNameAsync("NO.SUCH.USER", CancellationToken.None));
    }

    [Fact]
    public async Task FindByEmailAsync_matches_on_the_normalized_email()
    {
        var store = NewStore();
        var user = User("by.email", "By.Email@example.test");
        await store.CreateAsync(user, CancellationToken.None);

        var found = await store.FindByEmailAsync("BY.EMAIL@EXAMPLE.TEST", CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal(user.Id, found!.Id);
    }

    [Fact]
    public async Task UpdateAsync_persists_a_changed_password_hash()
    {
        var store = NewStore();
        var user = User("rotates", "rotates@example.test");
        await store.CreateAsync(user, CancellationToken.None);

        await store.SetPasswordHashAsync(user, "hash-after-reset", CancellationToken.None);
        await store.UpdateAsync(user, CancellationToken.None);

        var reloaded = await store.FindByIdAsync(user.Id!, CancellationToken.None);
        Assert.Equal("hash-after-reset", await store.GetPasswordHashAsync(reloaded!, CancellationToken.None));
    }

    [Fact]
    public async Task DeleteAsync_removes_the_user()
    {
        var store = NewStore();
        var user = User("transient", "transient@example.test");
        await store.CreateAsync(user, CancellationToken.None);

        await store.DeleteAsync(user, CancellationToken.None);

        Assert.Null(await store.FindByIdAsync(user.Id!, CancellationToken.None));
    }

    [Fact]
    public async Task GetUserIdAsync_refuses_a_user_that_was_never_persisted()
    {
        var store = NewStore();

        // IUserStore promises a non-null id, so this is the one accessor that throws rather than
        // widening to null when the contract cannot be met.
        var unsaved = new CustomIdentityUser { Id = null };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.GetUserIdAsync(unsaved, CancellationToken.None));
    }

    [Fact]
    public async Task HasPasswordAsync_reflects_whether_a_hash_is_set()
    {
        var store = NewStore();
        var user = User("no.password", "no.password@example.test");

        Assert.False(await store.HasPasswordAsync(user, CancellationToken.None));

        await store.SetPasswordHashAsync(user, "something", CancellationToken.None);

        Assert.True(await store.HasPasswordAsync(user, CancellationToken.None));
    }
}
