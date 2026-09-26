using System.Net;
using CPE.DapperIdentity.Jwt.Server;
using CPE.DapperIdentity.Stores.SignIn;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DapperIdentity.Tests;

/// <summary>
/// Pins the sign-in events PortGuardian reads (its D-067): the positional values it parses, what each
/// Identity outcome is reported as, and that reporting can never break a sign-in.
/// </summary>
public class SignInReportingTests
{
    private static HttpContext From(string address)
    {
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = IPAddress.Parse(address);
        return http;
    }

    [Fact]
    public void A_failure_is_written_as_seven_positional_values()
    {
        var attempt = SignInAttempt.Failure(From("203.0.113.9"), "bob", SignInFailure.BadPassword, "jwt");

        var values = SignInEventFormat.Values(attempt, "203.0.113.9", "BlazorHenemader");

        Assert.Equal(
            ["Sign-in failed for 'bob' from 203.0.113.9 on BlazorHenemader (jwt): BadPassword.",
             "1", "203.0.113.9", "bob", "BadPassword", "BlazorHenemader", "jwt"],
            values);
    }

    [Fact]
    public void A_success_has_no_reason_and_a_missing_username_is_empty()
    {
        var attempt = SignInAttempt.Success(From("203.0.113.9"), null, "cookie");

        var values = SignInEventFormat.Values(attempt, "203.0.113.9", "App");

        Assert.Equal("", values[3]);
        Assert.Equal("", values[4]);
        Assert.StartsWith("Sign-in succeeded", values[0], StringComparison.Ordinal);
    }

    [Fact]
    public void An_ipv4_client_seen_through_a_dual_stack_socket_is_reported_as_ipv4()
    {
        var attempt = SignInAttempt.Failure(From("::ffff:203.0.113.9"), "bob", SignInFailure.Unspecified, "cookie");

        Assert.Equal(IPAddress.Parse("203.0.113.9"), attempt.ClientIp);
    }

    [Fact]
    public void A_real_ipv6_client_is_kept_as_it_is()
    {
        var attempt = SignInAttempt.Failure(From("2001:db8::7"), "bob", SignInFailure.Unspecified, "cookie");

        Assert.Equal(IPAddress.Parse("2001:db8::7"), attempt.ClientIp);
    }

    public static TheoryData<string, bool?, SignInFailure> SignInOutcomes => new()
    {
        { nameof(SignInResult.Success), true, SignInFailure.Unspecified },
        // Only asked for a user who exists, so Failed is a wrong password.
        { nameof(SignInResult.Failed), false, SignInFailure.BadPassword },
        { nameof(SignInResult.LockedOut), false, SignInFailure.LockedOut },
        // Identity answers NotAllowed before it checks the password, so it is a failed try.
        { nameof(SignInResult.NotAllowed), false, SignInFailure.Unspecified },
        // The password was right and the second step is still to come: nothing to report yet.
        { nameof(SignInResult.TwoFactorRequired), null, SignInFailure.Unspecified },
    };

    [Theory]
    [MemberData(nameof(SignInOutcomes))]
    public void Each_sign_in_outcome_is_reported_as_what_it_means(string outcome, bool? succeeded, SignInFailure reason)
    {
        var result = outcome switch
        {
            nameof(SignInResult.Success) => SignInResult.Success,
            nameof(SignInResult.Failed) => SignInResult.Failed,
            nameof(SignInResult.LockedOut) => SignInResult.LockedOut,
            nameof(SignInResult.NotAllowed) => SignInResult.NotAllowed,
            _ => SignInResult.TwoFactorRequired,
        };

        var attempt = SignInAttempt.FromSignInResult(result, From("203.0.113.9"), "bob", "cookie");

        if (succeeded is null)
        {
            Assert.Null(attempt);
            return;
        }
        Assert.NotNull(attempt);
        Assert.Equal((succeeded.Value, reason, "bob", "cookie"), (attempt.Succeeded, attempt.Reason, attempt.UserName, attempt.Path));
    }

    [Fact]
    public void A_failure_is_one_warning_event_1000_and_a_success_one_information_event_1001()
    {
        var written = new List<(int Id, bool Warning, string[] Values)>();
        var reporter = Reporter(new CapturingLogs(), (id, warning, values) => written.Add((id, warning, values)));

        reporter.Report(SignInAttempt.Failure(From("203.0.113.9"), "bob", SignInFailure.BadPassword, "jwt"));
        reporter.Report(SignInAttempt.Success(From("203.0.113.9"), "bob", "jwt"));

        Assert.Equal(2, written.Count);
        Assert.Equal((1000, true), (written[0].Id, written[0].Warning));
        Assert.Equal((1001, false), (written[1].Id, written[1].Warning));
        Assert.Equal("TestApp", written[0].Values[5]);
        Assert.Equal("PortGuardian.SignIn", SignInEventFormat.Source); // the name PortGuardian subscribes to
    }

    [Fact]
    public void Every_attempt_is_logged_at_information_under_its_own_category()
    {
        var logs = new CapturingLogs();
        var reporter = Reporter(logs, (_, _, _) => { });

        reporter.Report(SignInAttempt.Failure(From("203.0.113.9"), "bob", SignInFailure.BadPassword, "jwt"));

        var entry = Assert.Single(logs.Entries);
        Assert.Equal(("CPE.DapperIdentity.SignIn", LogLevel.Information, 1000), (entry.Category, entry.Level, entry.EventId.Id));
        Assert.Contains("203.0.113.9", entry.Message, StringComparison.Ordinal);
        Assert.Contains("bob", entry.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void An_attempt_without_an_address_is_logged_but_not_written_as_an_event()
    {
        var logs = new CapturingLogs();
        var written = 0;
        var reporter = Reporter(logs, (_, _, _) => written++);

        reporter.Report(SignInAttempt.Failure(new DefaultHttpContext(), "bob", SignInFailure.BadPassword, "jwt"));

        Assert.Equal(0, written);
        Assert.Single(logs.Entries);
    }

    [Fact]
    public void A_failing_event_log_never_reaches_the_sign_in_and_is_not_tried_again()
    {
        var logs = new CapturingLogs();
        var tries = 0;
        var reporter = Reporter(logs, (_, _, _) =>
        {
            tries++;
            throw new System.Security.SecurityException("The source was not found, but some or all event logs could not be searched.");
        });

        var attempt = SignInAttempt.Failure(From("203.0.113.9"), "bob", SignInFailure.BadPassword, "jwt");
        reporter.Report(attempt);
        reporter.Report(attempt);

        Assert.Equal(1, tries);
        Assert.False(reporter.EventLogOn);
        Assert.Single(logs.Entries, e => e.Level == LogLevel.Warning);
        Assert.Equal(2, logs.Entries.Count(e => e.Level == LogLevel.Information));
    }

    [Fact]
    public void The_default_reporter_is_registered_once_and_a_hosts_own_is_kept()
    {
        var mine = new RecordingReporter();
        var services = new ServiceCollection();
        services.AddSingleton<ISignInReporter>(mine);
        services.TryAddSignInReporter();
        Assert.Same(mine, services.BuildServiceProvider().GetRequiredService<ISignInReporter>());

        var plain = new ServiceCollection();
        plain.AddLogging();
        plain.AddSingleton<IHostEnvironment>(new TestHost());
        plain.TryAddSignInReporter();
        plain.TryAddSignInReporter();
        Assert.Single(plain, d => d.ServiceType == typeof(ISignInReporter));
        Assert.IsType<SignInReporter>(plain.BuildServiceProvider().GetRequiredService<ISignInReporter>());
    }

    public static TheoryData<string> SetUps => new() { "jwt", "cookies", "vanilla-ui" };

    [Theory]
    [MemberData(nameof(SetUps))]
    public void Every_set_up_signs_in_through_the_custom_manager_and_registers_a_reporter(string setUp)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        _ = setUp switch
        {
            "jwt" => services.AddJwtIdentity(JwtConfig()),
            "cookies" => services.AddDapperIdentityWithCustomCookies(TimeSpan.FromDays(1)),
            _ => services.AddDapperIdentityWithVanillaUIAndDefaults(TimeSpan.FromDays(1)),
        };

        // The custom manager is what refuses a disabled user and what reports; the stock one does neither.
        // AddIdentity registers the stock one first; the last registration is the one resolved.
        var manager = services.Last(d => d.ServiceType == typeof(SignInManager<CPE.DapperIdentity.Stores.Models.CustomIdentityUser>));
        Assert.Equal(typeof(CPE.DapperIdentity.Stores.CustomSignInManager), manager.ImplementationType);
        Assert.Contains(services, d => d.ServiceType == typeof(ISignInReporter));
    }

    private static SignInReporter Reporter(CapturingLogs logs, Action<int, bool, string[]> writeEvent) =>
        new(new TestHost(), logs, writeEvent);

    internal static IConfiguration JwtConfig() => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        [AppBaseUrl.ConfigurationKey] = "https://app.example.test",
        ["JwtTokenSettings:ValidIssuer"] = "test-issuer",
        ["JwtTokenSettings:ValidAudience"] = "test-audience",
        ["JwtTokenSettings:SymmetricSecurityKey"] = "a-test-signing-key-that-is-long-enough-for-hmac",
        ["JwtTokenSettings:JwtExpireSeconds"] = "900",
        ["JwtTokenSettings:RefreshTokenLifeDays"] = "4",
    }).Build();

    internal sealed class RecordingReporter : ISignInReporter
    {
        public List<SignInAttempt> Attempts { get; } = [];
        public void Report(SignInAttempt attempt) => Attempts.Add(attempt);
    }

    private sealed class TestHost : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private sealed record LogEntry(string Category, LogLevel Level, EventId EventId, string Message);

    /// <summary>A logger factory that keeps every entry, so the log line itself can be checked.</summary>
    private sealed class CapturingLogs : ILoggerFactory
    {
        public List<LogEntry> Entries { get; } = [];
        public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Entries);
        public void AddProvider(ILoggerProvider provider) { }
        public void Dispose() { }

        private sealed class Logger(string category, List<LogEntry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                entries.Add(new LogEntry(category, logLevel, eventId, formatter(state, exception)));
        }
    }
}
