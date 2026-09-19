using System;
using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace CPE.DapperIdentity.Jwt.Server;

/// <summary>
/// Defaults and limits for the JWT server package, and the configuration keys that override them.
/// </summary>
public static class DapperIdentityDefaults
{
    /// <summary>The configuration key that overrides <see cref="PasswordLinkLifetime"/>.</summary>
    public const string PasswordLinkLifetimeConfigurationKey = "DapperIdentity:PasswordLinkLifetime";

    /// <summary>
    /// How long a password-reset or registration link stays valid when nothing overrides it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is only the default. The value actually enforced - and quoted to the user in the
    /// email - is whatever <c>DataProtectionTokenProviderOptions.TokenLifespan</c> ends up as,
    /// which a consumer can change through <see cref="PasswordLinkLifetimeConfigurationKey"/> or
    /// with their own <c>Configure</c> call. The email reads the option rather than this constant
    /// precisely so that an override cannot leave it promising a lifetime the server no longer
    /// enforces.
    /// </para>
    /// <para>
    /// Honoured only if the Data Protection key ring is persisted. With an ephemeral key ring the
    /// real lifetime is "until the next restart", because the key that sealed the token is gone -
    /// see technical-spec 9r.
    /// </para>
    /// </remarks>
    public static readonly TimeSpan PasswordLinkLifetime = TimeSpan.FromHours(24);

    /// <summary>The shortest lifetime a configured value may have.</summary>
    /// <remarks>
    /// Mail can take several minutes to arrive, and a link that expires before the user can open it
    /// is a support call rather than a security gain.
    /// </remarks>
    public static readonly TimeSpan MinimumPasswordLinkLifetime = TimeSpan.FromMinutes(15);

    /// <summary>The longest lifetime a configured value may have.</summary>
    /// <remarks>
    /// A reset link is a credential that sits in a mailbox. Capping it stops a careless
    /// <c>"30.00:00:00"</c> from turning every inbox into a month-long way into the account.
    /// </remarks>
    public static readonly TimeSpan MaximumPasswordLinkLifetime = TimeSpan.FromHours(24);

    /// <summary>
    /// Reads the configured link lifetime, or the default when none is set.
    /// </summary>
    /// <remarks>
    /// Checks only that the value parses. The range is enforced on the option itself, so that it
    /// also applies to a lifetime set in code - which would otherwise bypass any check made here.
    /// </remarks>
    /// <param name="configuration">The application's configuration.</param>
    /// <returns>The configured lifetime, or <see cref="PasswordLinkLifetime"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="configuration"/> is null.</exception>
    /// <exception cref="InvalidOperationException">The value is present but is not a time span.</exception>
    public static TimeSpan ReadPasswordLinkLifetime(IConfiguration configuration)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var configured = configuration[PasswordLinkLifetimeConfigurationKey];
        if (string.IsNullOrWhiteSpace(configured)) return PasswordLinkLifetime;

        if (!TimeSpan.TryParse(configured, CultureInfo.InvariantCulture, out var parsed))
        {
            throw new InvalidOperationException(
                $"Configuration value '{PasswordLinkLifetimeConfigurationKey}' is '{configured}', " +
                "which is not a time span. Use hours:minutes:seconds, for example \"01:00:00\" " +
                "for one hour or \"00:30:00\" for thirty minutes.");
        }

        return parsed;
    }

    /// <summary>Whether a lifetime falls inside the permitted range.</summary>
    /// <param name="lifetime">The lifetime to check.</param>
    /// <returns>True when it is between the minimum and maximum, inclusive.</returns>
    public static bool IsPermittedPasswordLinkLifetime(TimeSpan lifetime) =>
        lifetime >= MinimumPasswordLinkLifetime && lifetime <= MaximumPasswordLinkLifetime;

    /// <summary>
    /// Writes a lifetime the way it should read in an email, for example "24 hours" or
    /// "90 minutes".
    /// </summary>
    /// <remarks>
    /// Whole hours read as hours; anything else reads as minutes, because "1.5 hours" is harder to
    /// act on than "90 minutes" for someone deciding whether to click now or later.
    /// </remarks>
    /// <param name="lifetime">The lifetime to describe.</param>
    /// <returns>A phrase that completes "This link expires in ...".</returns>
    public static string Describe(TimeSpan lifetime)
    {
        if (lifetime.TotalHours >= 1 && lifetime.Ticks % TimeSpan.TicksPerHour == 0)
        {
            var hours = (long)lifetime.TotalHours;
            return hours == 1 ? "1 hour" : $"{hours} hours";
        }

        var minutes = (long)Math.Round(lifetime.TotalMinutes);
        return minutes == 1 ? "1 minute" : $"{minutes} minutes";
    }
}
