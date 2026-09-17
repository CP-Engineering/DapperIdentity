using System;
using System.Linq;
using System.Reflection;
using CPE.DapperIdentity.Stores.Models;
using Dapper.Contrib.Extensions;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// Asserts that the shipped creation script produces exactly the columns the models expect.
/// </summary>
/// <remarks>
/// This is the guard that was missing. On 2026-09-16 the scripts had drifted four ways from the
/// models — three absent columns on IdentityUser, one on IdentityRole, and the whole
/// IdentityUserClaim table — and nothing noticed, because nothing compared them. Moving the DDL
/// into C# would not have helped; only a comparison does.
/// </remarks>
public sealed class SchemaMatchesModelsTests : IClassFixture<SqliteSchemaFixture>
{
    private readonly SqliteSchemaFixture _fixture;

    public SchemaMatchesModelsTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    [Theory]
    [InlineData(typeof(CustomIdentityUser))]
    [InlineData(typeof(CustomIdentityRole))]
    [InlineData(typeof(CustomIdentityUserClaim))]
    public void Script_creates_exactly_the_columns_the_model_maps(Type model)
    {
        var table = model.GetCustomAttribute<TableAttribute>()?.Name
                    ?? throw new InvalidOperationException($"{model.Name} has no [Table] attribute.");

        // Dapper.Contrib persists every public read/write property except those marked [Write(false)].
        var expected = model.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                            .Where(p => p.CanRead && p.CanWrite)
                            .Where(p => p.GetCustomAttribute<WriteAttribute>()?.Write != false)
                            .Select(p => p.Name)
                            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                            .ToArray();

        var actual = _fixture.ColumnsOf(table)
                             .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                             .ToArray();

        Assert.False(actual.Length == 0, $"The script created no table named '{table}'.");

        var missing = expected.Except(actual, StringComparer.OrdinalIgnoreCase).ToArray();
        var extra = actual.Except(expected, StringComparer.OrdinalIgnoreCase).ToArray();

        Assert.True(
            missing.Length == 0 && extra.Length == 0,
            $"'{table}' does not match {model.Name}. " +
            $"Missing from the script: [{string.Join(", ", missing)}]. " +
            $"In the script but not on the model: [{string.Join(", ", extra)}].");
    }
}
