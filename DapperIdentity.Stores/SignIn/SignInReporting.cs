using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

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

/// <summary>How the name typed at a failed sign-in is written. A successful sign-in never carries one.</summary>
public enum SignInUserNames
{
    /// <summary>
    /// <c>sha256:</c> and the hash of the trimmed, lower-cased name. Enough for PortGuardian to recognise the owner's own
    /// names (it hashes its configured names the same way) without writing anyone's name or email in clear. Pseudonymous,
    /// not anonymous: whoever already holds a list of names can hash them and look for a match.
    /// </summary>
    Hashed,

    /// <summary>The name as typed (cleaned of line breaks and control characters). The most useful, and personal data.</summary>
    Plain,

    /// <summary>No name at all. Bans still work - they go by address - but nothing shows which accounts are attacked.</summary>
    None,
}

/// <summary>
/// Settings for sign-in reporting, bound from <c>DapperIdentity:SignInReporting</c> in configuration, or set in code with
/// <c>services.Configure&lt;SignInReportingOptions&gt;(...)</c>.
/// </summary>
/// <example><code>"DapperIdentity": { "SignInReporting": { "UserNames": "Plain" } }</code></example>
public sealed class SignInReportingOptions
{
    /// <summary>The configuration section these are read from.</summary>
    public const string SectionName = "DapperIdentity:SignInReporting";

    /// <summary>How the name typed at a failed sign-in is written; <see cref="SignInUserNames.Hashed"/> unless set.</summary>
    public SignInUserNames UserNames { get; set; } = SignInUserNames.Hashed;
}

/// <summary>
/// Binds <see cref="SignInReportingOptions"/> from configuration when the host has any; a host without configuration
/// (a test, a console tool) keeps the defaults instead of failing to start.
/// </summary>
internal sealed class SignInReportingOptionsFromConfiguration(IServiceProvider services) : IConfigureOptions<SignInReportingOptions>
{
    public void Configure(SignInReportingOptions options) =>
        services.GetService<IConfiguration>()?.GetSection(SignInReportingOptions.SectionName).Bind(options);
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

    /// <summary>The longest username written; anything past it is an attack on the log, not a name.</summary>
    public const int MaxUserNameLength = 256;

    /// <summary>The prefix of a hashed name, so a reader can tell it from a name that happens to look like hex.</summary>
    public const string HashPrefix = "sha256:";

    /// <summary>
    /// [0] a sentence for Event Viewer, [1] version, [2] IP, [3] the name as <paramref name="userNames"/> says (empty on
    /// success), [4] reason (empty on success), [5] app, [6] path.
    /// </summary>
    public static string[] Values(SignInAttempt attempt, string ip, string appName, SignInUserNames userNames = SignInUserNames.Hashed)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        var user = UserNameFor(attempt, userNames);
        // A success carries no name, so its sentence names none - "for ''" read like a bug.
        var sentence = attempt.Succeeded
            ? $"Sign-in succeeded from {ip} on {appName} ({attempt.Path})."
            : $"Sign-in failed for '{user}' from {ip} on {appName} ({attempt.Path}): {attempt.Reason}.";
        return [sentence, Version, ip, user, attempt.Succeeded ? "" : attempt.Reason.ToString(), appName, attempt.Path];
    }

    /// <summary>
    /// The name to write for <paramref name="attempt"/>: nothing for a success (the address is all it is reported for),
    /// otherwise the typed name hashed, plain or left out.
    /// </summary>
    public static string UserNameFor(SignInAttempt attempt, SignInUserNames userNames)
    {
        ArgumentNullException.ThrowIfNull(attempt);
        if (attempt.Succeeded || userNames == SignInUserNames.None)
            return "";

        var clean = Clean(attempt.UserName);
        return userNames == SignInUserNames.Plain ? clean : Hash(clean);
    }

    /// <summary>
    /// <see cref="HashPrefix"/> and the SHA-256 of the trimmed, lower-cased name, in lower-case hex; empty for no name.
    /// PortGuardian computes the same for its owner names, so this is a contract: the normalisation must not change
    /// without a new <see cref="Version"/>.
    /// </summary>
    public static string Hash(string? userName)
    {
        var normalised = Clean(userName).Trim().ToLowerInvariant();
        if (normalised.Length == 0)
            return "";

        return HashPrefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalised))).ToLowerInvariant();
    }

    /// <summary>
    /// A username as typed, made safe to write into a log: line breaks and other control characters removed, and cut
    /// to <see cref="MaxUserNameLength"/>. It is the one value an attacker chooses freely, so without this a "name"
    /// holding a line break could forge a second log entry, and a megabyte one could fill the log.
    /// </summary>
    public static string Clean(string? userName)
    {
        if (string.IsNullOrEmpty(userName))
            return "";

        // The newline replacements first and explicitly: they are what log readers and scanners (CodeQL's log-forging
        // rule) look for; the pass after catches every other control character.
        var withoutBreaks = userName.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal);
        var cleaned = new string(withoutBreaks.Where(c => !char.IsControl(c)).ToArray());
        return cleaned.Length <= MaxUserNameLength ? cleaned : cleaned[..MaxUserNameLength];
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
    private readonly SignInUserNames _userNames;
    private readonly Action<int, bool, string[]>? _writeEvent;
    private volatile bool _eventLogOff;

    /// <summary>Reports under the host's application name, writing names as <paramref name="options"/> says.</summary>
    /// <param name="host">Supplies the application name written with each event.</param>
    /// <param name="loggers">Creates the <see cref="SignInEventFormat.LogCategory"/> logger.</param>
    /// <param name="options">How names are written (<see cref="SignInReportingOptions.SectionName"/>).</param>
    public SignInReporter(IHostEnvironment host, ILoggerFactory loggers, IOptions<SignInReportingOptions> options)
        : this(host, loggers, options, null)
    {
    }

    /// <param name="host">Supplies the application name written with each event.</param>
    /// <param name="loggers">Creates the <see cref="SignInEventFormat.LogCategory"/> logger.</param>
    /// <param name="options">How names are written.</param>
    /// <param name="writeEvent">Replaces the event-log write (tests): event id, whether it is a warning, the values. Null writes to the real event log.</param>
    internal SignInReporter(IHostEnvironment host, ILoggerFactory loggers, IOptions<SignInReportingOptions> options, Action<int, bool, string[]>? writeEvent)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(loggers);
        ArgumentNullException.ThrowIfNull(options);
        _appName = host.ApplicationName;
        _logger = loggers.CreateLogger(SignInEventFormat.LogCategory);
        _userNames = options.Value.UserNames;
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
        // Two templates, not one with blanks: a success has no name or reason to show, and an empty "for  from" or a
        // "(-)" in the log reads like something failed to fill in. The shared properties keep the same names.
        if (attempt.Succeeded)
        {
            _logger.LogInformation(
                new EventId(SignInEventFormat.SucceededId, "SignInSucceeded"),
                "Sign-in succeeded from {ClientIp} on {App} via {Path}",
                attempt.ClientIp, _appName, attempt.Path);
        }
        else
        {
            _logger.LogInformation(
                new EventId(SignInEventFormat.FailedId, "SignInFailed"),
                "Sign-in failed for {UserName} from {ClientIp} on {App} via {Path} ({Reason})",
                SignInEventFormat.UserNameFor(attempt, _userNames), attempt.ClientIp, _appName, attempt.Path, attempt.Reason.ToString());
        }

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
        var values = SignInEventFormat.Values(attempt, ip, _appName, _userNames);
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
