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
/// Round-trip coverage for <see cref="RoleStore"/>, against the shipped schema.
/// </summary>
/// <remarks>
/// Nine of these eleven members threw <c>NotImplementedException</c> until 2026-09-17, so this is
/// first coverage rather than regression coverage. The case that matters most is
/// <see cref="RoleStore.FindByNameAsync"/>: it compares <c>UPPER(Name)</c> because the table has
/// no NormalizedName column (D-054), and that decision has to be demonstrated rather than trusted.
/// </remarks>
public sealed class RoleStoreTests : IClassFixture<SqliteSchemaFixture>
{
    private readonly SqliteSchemaFixture _fixture;

    public RoleStoreTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    private RoleStore NewStore() =>
        new(_fixture.Services.GetRequiredService<IRepository<CustomIdentityRole>>());

    private static CustomIdentityRole Role(string name) =>
        new() { Name = name, Description = $"{name} role" };

    [Fact]
    public async Task CreateAsync_assigns_an_Id_when_the_caller_supplied_none()
    {
        var store = NewStore();
        var role = Role("Dispatcher");

        // CustomIdentityRole has no constructor that fills this in, unlike CustomIdentityUser -
        // so without the store assigning one the insert would write a null primary key.
        Assert.Null(role.Id);

        await store.CreateAsync(role, CancellationToken.None);

        Assert.False(string.IsNullOrWhiteSpace(role.Id));
    }

    [Fact]
    public async Task CreateAsync_keeps_an_Id_the_caller_supplied()
    {
        var store = NewStore();
        var role = Role("Auditor");
        role.Id = "auditor-fixed-id";

        await store.CreateAsync(role, CancellationToken.None);

        Assert.Equal("auditor-fixed-id", role.Id);
        Assert.NotNull(await store.FindByIdAsync("auditor-fixed-id", CancellationToken.None));
    }

    [Fact]
    public async Task FindByIdAsync_returns_the_stored_role()
    {
        var store = NewStore();
        var role = Role("Receptionist");
        await store.CreateAsync(role, CancellationToken.None);

        var found = await store.FindByIdAsync(role.Id!, CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal("Receptionist", found!.Name);
        Assert.Equal("Receptionist role", found.Description);
    }

    [Fact]
    public async Task FindByIdAsync_returns_null_for_an_unknown_id()
    {
        var store = NewStore();

        Assert.Null(await store.FindByIdAsync(Guid.NewGuid().ToString(), CancellationToken.None));
    }

    /// <summary>
    /// The D-054 decision, demonstrated: Identity hands the store an upper-cased name, and the
    /// store has to find a row stored in its original casing.
    /// </summary>
    [Fact]
    public async Task FindByNameAsync_matches_the_upper_cased_name_Identity_passes()
    {
        var store = NewStore();
        await store.CreateAsync(Role("Veterinarian"), CancellationToken.None);

        var found = await store.FindByNameAsync("VETERINARIAN", CancellationToken.None);

        Assert.NotNull(found);
        Assert.Equal("Veterinarian", found!.Name);
    }

    [Fact]
    public async Task FindByNameAsync_returns_null_for_an_unknown_name()
    {
        var store = NewStore();

        Assert.Null(await store.FindByNameAsync("NOBODY", CancellationToken.None));
    }

    [Fact]
    public async Task GetNormalizedRoleNameAsync_derives_the_name_it_searches_by()
    {
        var store = NewStore();
        var role = Role("Technician");

        var normalized = await store.GetNormalizedRoleNameAsync(role, CancellationToken.None);

        // Must agree with what FindByNameAsync compares, or a round trip through Identity misses.
        Assert.Equal("TECHNICIAN", normalized);
    }

    [Fact]
    public async Task SetNormalizedRoleNameAsync_is_a_no_op_and_does_not_disturb_the_name()
    {
        var store = NewStore();
        var role = Role("Groomer");

        await store.SetNormalizedRoleNameAsync(role, "SOMETHING-ELSE", CancellationToken.None);

        Assert.Equal("Groomer", role.Name);
    }

    [Fact]
    public async Task UpdateAsync_persists_a_renamed_role()
    {
        var store = NewStore();
        var role = Role("Temp");
        await store.CreateAsync(role, CancellationToken.None);

        await store.SetRoleNameAsync(role, "Permanent", CancellationToken.None);
        await store.UpdateAsync(role, CancellationToken.None);

        var reloaded = await store.FindByIdAsync(role.Id!, CancellationToken.None);
        Assert.Equal("Permanent", reloaded!.Name);

        // And the rename must be visible to the lookup Identity actually uses.
        Assert.NotNull(await store.FindByNameAsync("PERMANENT", CancellationToken.None));
        Assert.Null(await store.FindByNameAsync("TEMP", CancellationToken.None));
    }

    [Fact]
    public async Task DeleteAsync_removes_the_role()
    {
        var store = NewStore();
        var role = Role("Obsolete");
        await store.CreateAsync(role, CancellationToken.None);

        await store.DeleteAsync(role, CancellationToken.None);

        Assert.Null(await store.FindByIdAsync(role.Id!, CancellationToken.None));
    }

    [Fact]
    public async Task GetRoleIdAsync_refuses_a_role_that_was_never_persisted()
    {
        var store = NewStore();

        // IRoleStore promises a non-null id here, so a role without one is a programming error
        // rather than something to paper over with an empty string.
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => store.GetRoleIdAsync(Role("Unsaved"), CancellationToken.None));
    }
}
