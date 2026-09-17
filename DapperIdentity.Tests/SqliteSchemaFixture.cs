using System;
using System.IO;
using CPE.DapperIdentity.Stores.Models;
using DapperRepository;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace DapperIdentity.Tests;

/// <summary>
/// A throwaway SQLite database built by executing the library's own shipped creation script.
/// </summary>
/// <remarks>
/// <para>
/// The point of running <c>SQL_Create/Sqlite.txt</c> rather than a schema written for the tests is
/// that it makes every test here evidence about the artifact a consumer actually receives. A
/// hand-written fixture schema would have passed happily while the shipped script was missing three
/// columns and an entire table, which is exactly what it was doing until 2026-09-16.
/// </para>
/// <para>
/// A temp file rather than <c>:memory:</c>. An in-memory SQLite database lives and dies with its
/// connection, and <see cref="IRepository{T}"/> hands out a fresh connection per call — so the
/// schema would vanish between the fixture creating it and a store using it. A file costs
/// microseconds here and removes a whole class of confusing failure.
/// </para>
/// </remarks>
public sealed class SqliteSchemaFixture : IDisposable
{
    private readonly string _databasePath;

    public string ConnectionString { get; }

    public ServiceProvider Services { get; }

    public SqliteSchemaFixture()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"dapperidentity-tests-{Guid.NewGuid():N}.db");
        ConnectionString = $"Data Source={_databasePath}";

        ExecuteScript(ScriptPath("Sqlite.txt"));

        var services = new ServiceCollection();
        services.AddDbConnectionInstantiatorForRepositories<SqliteConnection>(ConnectionString);
        services.AddTransientRepository<CustomIdentityUser>();
        services.AddTransientRepository<CustomIdentityRole>();
        services.AddTransientRepository<CustomIdentityUserClaim>();
        Services = services.BuildServiceProvider();
    }

    /// <summary>The shipped script, copied beside the test assembly by the Stores project.</summary>
    public static string ScriptPath(string fileName)
        => Path.Combine(AppContext.BaseDirectory, "SQL_Create", fileName);

    private void ExecuteScript(string path)
    {
        var sql = File.ReadAllText(path);

        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    /// <summary>Column names SQLite reports for a table, which is the script's actual effect.</summary>
    public string[] ColumnsOf(string table)
    {
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = $"PRAGMA table_info(\"{table}\");";

        var columns = new System.Collections.Generic.List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            columns.Add(reader.GetString(1));
        }

        return columns.ToArray();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }
}
