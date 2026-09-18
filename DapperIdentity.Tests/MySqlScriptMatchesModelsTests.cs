using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using CPE.DapperIdentity.Stores.Models;
using Dapper.Contrib.Extensions;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// The same drift guard as <see cref="SchemaMatchesModelsTests"/>, for the dialect production
/// actually runs.
/// </summary>
/// <remarks>
/// <para>
/// The SQLite guard executes the script and asks the database what it built, which is stronger
/// evidence - but it protects the dialect nobody deploys. MySQL is what DVMApp runs on, and
/// `mysql.txt` is where three of the four defects found on 2026-09-16 lived. Leaving it unguarded
/// would mean the guard covers the copy that cannot drift in a way anyone notices.
/// </para>
/// <para>
/// This reads the DDL as text instead of executing it, so it needs no MySQL and no Docker and
/// runs anywhere. That buys the column-set check - which is the drift that actually happened -
/// and nothing else: a wrong type, a missing PRIMARY KEY or a bad collation all pass here.
/// Executing the real script against a container is tracked separately.
/// </para>
/// </remarks>
public class MySqlScriptMatchesModelsTests
{
    [Theory]
    [InlineData(typeof(CustomIdentityUser))]
    [InlineData(typeof(CustomIdentityRole))]
    [InlineData(typeof(CustomIdentityUserClaim))]
    public void Script_declares_exactly_the_columns_the_model_maps(Type model)
    {
        var table = model.GetCustomAttribute<TableAttribute>()?.Name
                    ?? throw new InvalidOperationException($"{model.Name} has no [Table] attribute.");

        var expected = model.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                            .Where(p => p.CanRead && p.CanWrite)
                            .Where(p => p.GetCustomAttribute<WriteAttribute>()?.Write != false)
                            .Select(p => p.Name)
                            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                            .ToArray();

        var actual = ColumnsDeclaredFor(table)
                     .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                     .ToArray();

        Assert.True(actual.Length > 0, $"mysql.txt declares no table named '{table}'.");

        var missing = expected.Except(actual, StringComparer.OrdinalIgnoreCase).ToArray();
        var extra = actual.Except(expected, StringComparer.OrdinalIgnoreCase).ToArray();

        Assert.True(
            missing.Length == 0 && extra.Length == 0,
            $"mysql.txt '{table}' does not match {model.Name}. " +
            $"Missing from the script: [{string.Join(", ", missing)}]. " +
            $"In the script but not on the model: [{string.Join(", ", extra)}].");
    }

    /// <summary>
    /// Pulls the column names out of one CREATE TABLE block.
    /// </summary>
    /// <remarks>
    /// The script is MySQL Workbench output, so every identifier is backtick-quoted and every
    /// column definition starts its line with one. Constraint lines (`PRIMARY KEY (...)`) start
    /// with a keyword instead, which is what keeps them out without needing to parse SQL.
    /// </remarks>
    private static IEnumerable<string> ColumnsDeclaredFor(string table)
    {
        var script = File.ReadAllText(SqliteSchemaFixture.ScriptPath("mysql.txt"));

        var block = Regex.Match(
            script,
            @"CREATE\s+TABLE\s+`" + Regex.Escape(table) + @"`\s*\((?<body>.*?)\n\)",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);

        if (!block.Success) yield break;

        foreach (Match column in Regex.Matches(block.Groups["body"].Value, @"(?m)^\s*`(?<name>[^`]+)`\s+\S"))
        {
            yield return column.Groups["name"].Value;
        }
    }

    [Fact]
    public void The_parser_itself_finds_something_to_check()
    {
        // A regex that silently matched nothing would make every assertion above vacuous, so the
        // guard needs a guard: this fails if the script's shape ever stops being what is parsed.
        Assert.NotEmpty(ColumnsDeclaredFor("IdentityUser"));
        Assert.NotEmpty(ColumnsDeclaredFor("IdentityRole"));
        Assert.NotEmpty(ColumnsDeclaredFor("IdentityUserClaim"));
    }
}
