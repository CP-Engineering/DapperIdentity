using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CPE.DapperIdentity.Stores.SignIn;

/// <summary>Why a sign-in failed. The names are PortGuardian's own, so they are written as they are.</summary>
public enum SignInFailure
{
    /// <summary>Refused for another reason before the password counted: not allowed (disabled, unconfirmed).</summary>
    Unspecified,
    /// <summary>The user exists and the password was wrong.</summary>
    BadPassword,
    /// <summary>No user has that name or email.</summary>
    UnknownUser,
    /// <summary>The account is locked out, so the password was not checked.</summary>
    LockedOut,
}

/// <summary>One sign-in's outcome, as the endpoint saw it.</summary>
/// <param name="Succeeded">Whether the sign-in went through.</param>
/// <param name="ClientIp">The address it came from; null when there was no request.</param>
/// <param name="UserName">The name or email as typed.</param>
/// <param name="Reason">Why it failed; <see cref="SignInFailure.Unspecified"/> on success.</param>
/// <param name="Path">Which sign-in endpoint: <c>cookie</c> or <c>jwt</c>.</param>
public sealed record SignInAttempt(bool Succeeded, IPAddress? ClientIp, string? UserName, SignInFailure Reason, string Path)
{
    /// <summary>A sign-in that went through, from the request's address.</summary>
    public static SignInAttempt Success(HttpContext? http, string? userName, string path) =>
        new(true, ClientAddress(http), userName, SignInFailure.Unspecified, path);

    /// <summary>A refused sign-in, from the request's address.</summary>
    public static SignInAttempt Failure(HttpContext? http, string? userName, SignInFailure reason, string path) =>
        new(false, ClientAddress(http), userName, reason, path);

    /// <summary>
    /// What a sign-in result for a user who exists means for reporting, or null when it is neither a
    /// finished sign-in nor a failed one. RequiresTwoFactor is that case: the password was right and
    /// the second step is still to come. Failed, for a user who exists, is a wrong password.
    /// NotAllowed and LockedOut are decided before the password is checked, so they are failed tries
    /// whatever was typed.
    /// </summary>
    public static SignInAttempt? FromSignInResult(SignInResult result, HttpContext? http, string? userName, string path)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Succeeded)
            return Success(http, userName, path);
        if (result.RequiresTwoFactor)
            return null;
        var reason = result.IsLockedOut ? SignInFailure.LockedOut
                   : result.IsNotAllowed ? SignInFailure.Unspecified
                   : SignInFailure.BadPassword;
        return Failure(http, userName, reason, path);
    }

    // Kestrel's dual-stack socket reports an IPv4 client as ::ffff:a.b.c.d; a firewall bans the IPv4 form.
    private static IPAddress? ClientAddress(HttpContext? http)
    {
        var address = http?.Connection.RemoteIpAddress;
        return address is { IsIPv4MappedToIPv6: true } ? address.MapToIPv4() : address;
    }
}

/// <summary>
/// Tells something outside the app that a sign-in happened. The default logs it and, on Windows,
/// writes it to the event log for PortGuardian; register your own first to feed something else.
/// </summary>
public interface ISignInReporter
{
    /// <summary>Records one attempt. Must not throw; the caller guards against it anyway.</summary>
    void Report(SignInAttempt attempt);
}

/// <summary>
/// The event-log contract PortGuardian reads (its decision D-067). Values are positional and only
/// ever appended; <see cref="Version"/> rises if one changes meaning. Never a password, token or user id.
/// </summary>
public static class SignInEventFormat
{
    /// <summary>The Application-log source PortGuardian subscribes to; its installer registers it.</summary>
    public const string Source = "PortGuardian.SignIn";
    /// <summary>The <c>ILogger</c> category, so a host can raise, lower or silence the log line.</summary>
    public const string LogCategory = "CPE.DapperIdentity.SignIn";
    /// <summary>Event id of a failed sign-in.</summary>
    public const int FailedId = 1000;
    /// <summary>Event id of a successful sign-in.</summary>
    public const int SucceededId = 1001;
    /// <summary>The format version, written as value [1].</summary>
    public const string Version = "1";

    /// <summary>[0] a sentence for Event Viewer, [1] version, [2] IP, [3] username as typed, [4] reason (empty on success), [5] app, [6] path.</summary>
    public static string[] Values(SignInAttempt attempt, string ip, string appName)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        var user = attempt.UserName ?? "";
        var sentence = attempt.Succeeded
            ? $"Sign-in succeeded for '{user}' from {ip} on {appName} ({attempt.Path})."
            : $"Sign-in failed for '{user}' from {ip} on {appName} ({attempt.Path}): {attempt.Reason}.";
        return [sentence, Version, ip, user, attempt.Succeeded ? "" : attempt.Reason.ToString(), appName, attempt.Path];
    }
}

/// <summary>
/// The default reporter: one log line on every OS, and on Windows one Application-log event under
/// <see cref="SignInEventFormat.Source"/>. Never throws: a sign-in must not fail because reporting did.
/// </summary>
public sealed class SignInReporter : ISignInReporter
{
    private readonly string _appName;
    private readonly ILogger _logger;
    private readonly Action<int, bool, string[]>? _writeEvent;
    private volatile bool _eventLogOff;

    /// <summary>Reports under the host's application name.</summary>
    /// <param name="host">Supplies the application name written with each event.</param>
    /// <param name="loggers">Creates the <see cref="SignInEventFormat.LogCategory"/> logger.</param>
    public SignInReporter(IHostEnvironment host, ILoggerFactory loggers)
        : this(host, loggers, null)
    {
    }

    /// <param name="host">Supplies the application name written with each event.</param>
    /// <param name="loggers">Creates the <see cref="SignInEventFormat.LogCategory"/> logger.</param>
    /// <param name="writeEvent">Replaces the event-log write (tests): event id, whether it is a warning, the values. Null writes to the real event log.</param>
    internal SignInReporter(IHostEnvironment host, ILoggerFactory loggers, Action<int, bool, string[]>? writeEvent)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(loggers);
        _appName = host.ApplicationName;
        _logger = loggers.CreateLogger(SignInEventFormat.LogCategory);
        _writeEvent = writeEvent;
    }

    /// <summary>False once an event-log write has failed; it stays so until the app restarts.</summary>
    public bool EventLogOn => !_eventLogOff;

    /// <inheritdoc />
    public void Report(SignInAttempt attempt)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        // Information, not Warning: on Windows ASP.NET Core's default event-log logger takes Warning and
        // up, so a Warning here would add a second Application-log entry per attempt during an attack.
        _logger.LogInformation(
            new EventId(attempt.Succeeded ? SignInEventFormat.SucceededId : SignInEventFormat.FailedId,
                        attempt.Succeeded ? "SignInSucceeded" : "SignInFailed"),
            "Sign-in {Outcome} for {UserName} from {ClientIp} on {App} via {Path} ({Reason})",
            attempt.Succeeded ? "succeeded" : "failed", attempt.UserName, attempt.ClientIp, _appName, attempt.Path,
            attempt.Succeeded ? "-" : attempt.Reason.ToString());

        // No address, nothing to ban: PortGuardian has no use for the event.
        if (_eventLogOff || attempt.ClientIp is null)
            return;
        if (_writeEvent is null && !OperatingSystem.IsWindows())
            return;

        WriteEvent(attempt, attempt.ClientIp.ToString());
    }

    private void WriteEvent(SignInAttempt attempt, string ip)
    {
        var id = attempt.Succeeded ? SignInEventFormat.SucceededId : SignInEventFormat.FailedId;
        var warning = !attempt.Succeeded;
        var values = SignInEventFormat.Values(attempt, ip, _appName);
        try
        {
            if (_writeEvent is not null)
                _writeEvent(id, warning, values);
            else if (OperatingSystem.IsWindows())
                WriteToEventLog(id, warning, values);
        }
#pragma warning disable CA1031 // Any failure here must stay out of the sign-in.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // Almost always the source isn't registered (PortGuardian not installed) and an app pool may
            // not create one. Say so once and stop, rather than throwing on every attempt of an attack.
            _eventLogOff = true;
            _logger.LogWarning(ex,
                "Sign-in events are off until the app restarts: could not write to the event log as {Source}. "
                + "PortGuardian's installer registers it; without PortGuardian nothing reads them.",
                SignInEventFormat.Source);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void WriteToEventLog(int id, bool warning, string[] values) =>
        EventLog.WriteEvent(SignInEventFormat.Source,
            new EventInstance(id, 0, warning ? EventLogEntryType.Warning : EventLogEntryType.Information), values);
}
