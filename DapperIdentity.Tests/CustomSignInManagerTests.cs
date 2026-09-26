using System.Net;
using CPE.DapperIdentity.Stores;
using CPE.DapperIdentity.Stores.Models;
using CPE.DapperIdentity.Stores.SignIn;
using DapperRepository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace DapperIdentity.Tests;

/// <summary>
/// The sign-in manager as the JWT package wires it, over the real SQLite schema: every attempt is
/// reported, and a token sign-in refuses exactly whom a cookie sign-in refuses.
/// </summary>
/// <remarks>
/// Before this, the JWT sign-in checked only the password hash (UserManager.CheckPasswordAsync), so a
/// user with IsEnabled = false still got a token. These tests are the proof that it no longer does.
/// </remarks>
public sealed class CustomSignInManagerTests : IClassFixture<SqliteSchemaFixture>
{
    private const string Password = "correct-horse";
    private readonly SqliteSchemaFixture _fixture;

    public CustomSignInManagerTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    private sealed class Harness : IDisposable
    {
        private readonly ServiceProvider _root;
        private readonly IServiceScope _scope;

        public Harness(string connectionString)
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton<ISignInReporter>(Reports);
            services.AddDbConnectionInstantiatorForRepositories<SqliteConnection>(connectionString);
            services.AddJwtIdentity(SignInReportingTests.JwtConfig());
            _root = services.BuildServiceProvider();
            _scope = _root.CreateScope();

            var http = new DefaultHttpContext { RequestServices = _scope.ServiceProvider };
            http.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.9");
            _scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = http;
        }

        public SignInReportingTests.RecordingReporter Reports { get; } = new();
        public CustomSignInManager Manager => _scope.ServiceProvider.GetRequiredService<CustomSignInManager>();
        public UserManager<CustomIdentityUser> Users => _scope.ServiceProvider.GetRequiredService<UserManager<CustomIdentityUser>>();

        public async Task<CustomIdentityUser> CreateAsync(bool enabled = true)
        {
            var name = $"user-{Guid.NewGuid():N}";
            var user = new CustomIdentityUser { UserName = name, Email = $"{name}@example.test", IsEnabled = enabled };
            var created = await Users.CreateAsync(user, Password);
            Assert.True(created.Succeeded, string.Join("; ", created.Errors.Select(e => e.Description)));
            return user;
        }

        public void Dispose()
        {
            _scope.Dispose();
            _root.Dispose();
        }
    }

    [Fact]
    public async Task A_token_sign_in_with_the_right_password_returns_the_user_and_reports_a_success()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();

        var (result, signedIn) = await h.Manager.CheckPasswordByEmailAsync(user.Email!, Password);

        Assert.True(result.Succeeded);
        Assert.Equal(user.Id, signedIn?.Id);
        var report = Assert.Single(h.Reports.Attempts);
        Assert.Equal((true, "jwt", user.Email, IPAddress.Parse("203.0.113.9")), (report.Succeeded, report.Path, report.UserName, report.ClientIp));
    }

    [Fact]
    public async Task A_disabled_user_gets_no_token_even_with_the_right_password()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync(enabled: false);

        var (result, signedIn) = await h.Manager.CheckPasswordByEmailAsync(user.Email!, Password);

        Assert.True(result.IsNotAllowed);
        Assert.Null(signedIn);
        var report = Assert.Single(h.Reports.Attempts);
        Assert.False(report.Succeeded);
    }

    [Fact]
    public async Task A_wrong_password_and_an_unknown_email_are_reported_as_what_they_are()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();

        var (wrong, noUser) = await h.Manager.CheckPasswordByEmailAsync(user.Email!, "not-it");
        var (unknown, nobody) = await h.Manager.CheckPasswordByEmailAsync("nobody@example.test", Password);

        Assert.False(wrong.Succeeded);
        Assert.False(unknown.Succeeded);
        Assert.Null(noUser);
        Assert.Null(nobody);
        Assert.Equal([SignInFailure.BadPassword, SignInFailure.UnknownUser], h.Reports.Attempts.Select(a => a.Reason));
        Assert.All(h.Reports.Attempts, a => Assert.False(a.Succeeded));
    }

    [Fact]
    public async Task A_cookie_sign_in_by_name_reports_an_unknown_name_and_a_wrong_password()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();

        await h.Manager.PasswordSignInAsync("nobody", Password, isPersistent: false, lockoutOnFailure: false);
        await h.Manager.PasswordSignInAsync(user.UserName!, "not-it", isPersistent: false, lockoutOnFailure: false);

        Assert.Equal(
            [(SignInFailure.UnknownUser, "nobody"), (SignInFailure.BadPassword, user.UserName)],
            h.Reports.Attempts.Select(a => (a.Reason, a.UserName)));
        Assert.All(h.Reports.Attempts, a => Assert.Equal("cookie", a.Path));
    }

    [Fact]
    public async Task A_refresh_is_refused_once_the_user_is_disabled()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();
        Assert.True(await h.Manager.AllowsSignInAsync(user));

        user.IsEnabled = false;

        Assert.False(await h.Manager.AllowsSignInAsync(user));
        Assert.Empty(h.Reports.Attempts); // a refresh is not a password attempt
    }

    [Fact]
    public async Task A_reporter_that_throws_does_not_break_the_sign_in()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISignInReporter>(new ThrowingReporter());
        services.AddDbConnectionInstantiatorForRepositories<SqliteConnection>(_fixture.ConnectionString);
        services.AddJwtIdentity(SignInReportingTests.JwtConfig());
        using var root = services.BuildServiceProvider();
        using var scope = root.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<CustomIdentityUser>>();
        var name = $"user-{Guid.NewGuid():N}";
        var user = new CustomIdentityUser { UserName = name, Email = $"{name}@example.test", IsEnabled = true };
        Assert.True((await users.CreateAsync(user, Password)).Succeeded);

        var (result, signedIn) = await scope.ServiceProvider.GetRequiredService<CustomSignInManager>()
            .CheckPasswordByEmailAsync(user.Email!, Password);

        Assert.True(result.Succeeded);
        Assert.NotNull(signedIn);
    }

    private sealed class ThrowingReporter : ISignInReporter
    {
        public void Report(SignInAttempt attempt) => throw new InvalidOperationException("reporter down");
    }
}
