using System;
using Microsoft.Extensions.Configuration;

namespace CPE.DapperIdentity.Jwt.Server;

/// <summary>
/// The application's own public address, used to build links that reach users by email.
/// </summary>
/// <remarks>
/// <para>
/// This exists because the address has to come from configuration rather than from the request.
/// Until 2026-09-17 the password-reset link was built from the incoming <c>Referer</c> header,
/// which an unauthenticated caller sets to anything it likes - so a request to the anonymous
/// forgot-password endpoint could make the application email a real user a real reset token
/// pointing at someone else's domain (CWE-640, password-reset poisoning). Deriving it from
/// <c>Request.Host</c> instead would only move the same problem to a different header.
/// </para>
/// <para>
/// Registered by <c>AddJwtIdentity</c> from <c>DapperIdentity:AppBaseUrl</c>, which is required:
/// a missing or non-absolute value stops the application starting rather than producing links
/// that do not work.
/// </para>
/// </remarks>
public sealed class AppBaseUrl
{
    /// <summary>Wraps an absolute base address.</summary>
    /// <param name="value">
    /// The application's public root, for example <c>https://app.example.com</c>. A trailing
    /// slash is added when absent - see <see cref="PathTo"/> for why that matters.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="value"/> is not absolute.</exception>
    public AppBaseUrl(Uri value)
    {
        if (value is null) throw new ArgumentNullException(nameof(value));
        if (!value.IsAbsoluteUri) throw new ArgumentException("The base URL must be absolute.", nameof(value));

        // Relative-URI resolution replaces the last path segment when the base has no trailing
        // slash, so "https://host/app" + "Account/Reset" would silently lose "app". Normalising
        // here means a consumer can configure the value either way and get the same link.
        Value = value.AbsoluteUri.EndsWith("/", StringComparison.Ordinal)
            ? value
            : new Uri(value.AbsoluteUri + "/");
    }

    /// <summary>The base address, always ending in a slash.</summary>
    public Uri Value { get; }

    /// <summary>Resolves a path beneath the application root.</summary>
    /// <param name="relativePath">
    /// A path relative to the root, with no leading slash - for example
    /// <c>Account/PasswordReset</c>. A leading slash would resolve against the host instead and
    /// discard any path the base address carries.
    /// </param>
    /// <returns>The absolute URL.</returns>
    public Uri PathTo(string relativePath) => new Uri(Value, relativePath);

    /// <summary>The configuration key this is read from.</summary>
    public const string ConfigurationKey = "DapperIdentity:AppBaseUrl";

    /// <summary>
    /// Reads and validates the base address from configuration.
    /// </summary>
    /// <remarks>
    /// Required, with no fallback on purpose. The obvious fallback would be the incoming request,
    /// which is exactly what this type exists to stop the library trusting - so a deployment that
    /// has not set it must fail loudly rather than quietly return to the unsafe behaviour.
    /// <c>AddJwtIdentity</c> calls this during registration so the failure lands at startup, not
    /// at the moment a user needs a reset link.
    /// </remarks>
    /// <param name="configuration">The application's configuration.</param>
    /// <returns>The validated base address.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="configuration"/> is null.</exception>
    /// <exception cref="InvalidOperationException">
    /// The value is absent, blank, or not an absolute http/https URL.
    /// </exception>
    public static AppBaseUrl FromConfiguration(IConfiguration configuration)
    {
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        var configured = configuration[ConfigurationKey];

        if (string.IsNullOrWhiteSpace(configured))
        {
            throw new InvalidOperationException(
                $"Configuration is missing '{ConfigurationKey}'. Set it to this application's own " +
                "public address, for example \"https://app.example.com\". It is used to build the " +
                "password-reset link that is emailed to users, and has no safe default.");
        }

        if (!Uri.TryCreate(configured, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException(
                $"Configuration value '{ConfigurationKey}' is '{configured}', which is not an " +
                "absolute http or https URL. A relative value produces an unusable link in an email.");
        }

        return new AppBaseUrl(parsed);
    }
}
