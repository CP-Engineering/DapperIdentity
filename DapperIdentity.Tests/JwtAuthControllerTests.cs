using System.Net;
using CPE.DapperIdentity.Abstractions;
using CPE.DapperIdentity.Abstractions.Models;
using CPE.DapperIdentity.Jwt.Server;
using CPE.DapperIdentity.Jwt.Server.Controllers;
using CPE.DapperIdentity.Stores.Models;
using CPE.DapperIdentity.Stores.SignIn;
using DapperRepository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DapperIdentity.Tests;

/// <summary>
/// The JWT endpoints themselves, wired as AddJwtIdentity wires them, over the real SQLite schema.
/// </summary>
/// <remarks>
/// The sign-in manager's tests prove the manager refuses a disabled user; these prove the endpoints
/// ask it. Until 2026-09-26 <c>Authenticate</c> checked only the password hash and <c>Refresh</c>
/// checked nothing about the account, so a disabled user got and kept a token.
/// </remarks>
public sealed class JwtAuthControllerTests : IClassFixture<SqliteSchemaFixture>
{
    private const string Password = "correct-horse";
    private readonly SqliteSchemaFixture _fixture;

    public JwtAuthControllerTests(SqliteSchemaFixture fixture) => _fixture = fixture;

    private sealed class Harness : IDisposable
    {
        private readonly ServiceProvider _root;
        private readonly IServiceScope _scope;

        public Harness(string connectionString)
        {
            var configuration = SignInReportingTests.JwtConfig();
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddSingleton(configuration);
            services.AddSingleton<ISignInReporter>(Reports);
            services.AddSingleton<IAuthEmailSender>(new NoMail());
            services.AddIAppSettings(new TestAppSettings());
            services.AddDbConnectionInstantiatorForRepositories<SqliteConnection>(connectionString);
            services.AddJwtIdentity(configuration);
            _root = services.BuildServiceProvider();
            _scope = _root.CreateScope();

            var http = new DefaultHttpContext { RequestServices = _scope.ServiceProvider };
            http.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.9");
            _scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = http;

            Controller = ActivatorUtilities.CreateInstance<JwtAuthController>(_scope.ServiceProvider);
            Controller.ControllerContext = new ControllerContext { HttpContext = http };
        }

        public SignInReportingTests.RecordingReporter Reports { get; } = new();
        public JwtAuthController Controller { get; }
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
    public async Task The_right_password_gets_a_token_and_is_reported()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();

        var answer = await h.Controller.Authenticate(new AuthRequest { Email = user.Email, Password = Password });

        var ok = Assert.IsType<OkObjectResult>(answer.Result);
        Assert.False(string.IsNullOrEmpty(Assert.IsType<AuthResponse>(ok.Value).Token));
        var report = Assert.Single(h.Reports.Attempts);
        Assert.Equal((true, "jwt"), (report.Succeeded, report.Path));
    }

    [Fact]
    public async Task A_disabled_user_with_the_right_password_gets_no_token()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync(enabled: false);

        var answer = await h.Controller.Authenticate(new AuthRequest { Email = user.Email, Password = Password });

        // The same answer as a wrong password, so the reply does not reveal that the account exists.
        Assert.Equal("Bad credentials", Assert.IsType<BadRequestObjectResult>(answer.Result).Value);
        Assert.False(Assert.Single(h.Reports.Attempts).Succeeded);
    }

    [Fact]
    public async Task A_wrong_password_and_an_unknown_email_get_the_same_answer_and_are_reported()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();

        var wrong = await h.Controller.Authenticate(new AuthRequest { Email = user.Email, Password = "not-it" });
        var unknown = await h.Controller.Authenticate(new AuthRequest { Email = "nobody@example.test", Password = Password });

        Assert.Equal("Bad credentials", Assert.IsType<BadRequestObjectResult>(wrong.Result).Value);
        Assert.Equal("Bad credentials", Assert.IsType<BadRequestObjectResult>(unknown.Result).Value);
        Assert.Equal([SignInFailure.BadPassword, SignInFailure.UnknownUser], h.Reports.Attempts.Select(a => a.Reason));
    }

    [Fact]
    public async Task A_refresh_works_while_the_user_is_enabled_and_stops_once_disabled()
    {
        using var h = new Harness(_fixture.ConnectionString);
        var user = await h.CreateAsync();
        var first = (AuthResponse)Assert.IsType<OkObjectResult>(
            (await h.Controller.Authenticate(new AuthRequest { Email = user.Email, Password = Password })).Result).Value!;

        // The control: without it, a refresh broken for any reason would pass the refusal below.
        var renewed = (AuthResponse)Assert.IsType<OkObjectResult>(
            (await h.Controller.Refresh(new RefreshTokenDto { Token = first.Token, RefreshToken = first.RefreshToken })).Result).Value!;

        var stored = await h.Users.FindByIdAsync(user.Id!);
        stored!.IsEnabled = false;
        Assert.True((await h.Users.UpdateAsync(stored)).Succeeded);

        var refused = await h.Controller.Refresh(new RefreshTokenDto { Token = renewed.Token, RefreshToken = renewed.RefreshToken });

        Assert.IsType<BadRequestObjectResult>(refused.Result);
    }

    private sealed class NoMail : IAuthEmailSender
    {
        public Task SendEmailAsync(string email, string subject, string htmlMessage) => Task.CompletedTask;
    }

    private sealed class TestAppSettings : IAppSettings
    {
        public string ApplicationName => "TestApp";
    }
}
