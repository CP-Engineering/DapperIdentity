using CPE.DapperIdentity.Jwt.Server;

namespace DapperIdentity.Tests;

/// <summary>
/// Pins the reset-link construction that replaced the Referer header.
/// </summary>
/// <remarks>
/// The old code concatenated strings - <c>$"{referrer}Account/PasswordReset"</c> - and produced a
/// correct URL only because a cross-origin Referer happens to arrive as a bare origin with a
/// trailing slash. These tests exist so that accident cannot come back: whatever shape the
/// configured value has, the link must be the same.
/// </remarks>
public class PasswordResetLinkTests
{
    [Theory]
    [InlineData("https://app.example.com", "https://app.example.com/Account/PasswordReset")]
    [InlineData("https://app.example.com/", "https://app.example.com/Account/PasswordReset")]
    [InlineData("http://localhost:5001", "http://localhost:5001/Account/PasswordReset")]
    public void Builds_the_same_link_with_or_without_a_trailing_slash(string configured, string expected)
    {
        var baseUrl = new AppBaseUrl(new Uri(configured));

        Assert.Equal(expected, baseUrl.PathTo("Account/PasswordReset").AbsoluteUri);
    }

    [Theory]
    [InlineData("https://example.com/portal")]
    [InlineData("https://example.com/portal/")]
    public void Keeps_a_path_segment_in_the_base_address(string configured)
    {
        // Relative-URI resolution drops the last segment when the base has no trailing slash, so
        // "https://example.com/portal" would otherwise resolve to "https://example.com/Account/..."
        // and send users to a page that does not exist.
        var baseUrl = new AppBaseUrl(new Uri(configured));

        Assert.Equal(
            "https://example.com/portal/Account/PasswordReset",
            baseUrl.PathTo("Account/PasswordReset").AbsoluteUri);
    }

    [Fact]
    public void Rejects_a_relative_base_address()
    {
        Assert.Throws<ArgumentException>(() => new AppBaseUrl(new Uri("/app", UriKind.Relative)));
    }
}
