using System;
using System.Collections.Generic;
using CPE.DapperIdentity.Jwt.Server;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// Covers the startup guard on <c>DapperIdentity:AppBaseUrl</c>.
/// </summary>
/// <remarks>
/// This is guard code whose whole purpose is to fire on a bad deployment, so until something
/// watches it fire there is no evidence it works. A wrong key path would be invisible: the guard
/// would either never trigger - quietly returning to broken reset links - or always trigger, and
/// the API would refuse to start with the setting apparently present.
/// </remarks>
public class AppBaseUrlConfigurationTests
{
    private static IConfiguration ConfigWith(string? value)
    {
        var values = new Dictionary<string, string?>();
        if (value is not null) values[AppBaseUrl.ConfigurationKey] = value;

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    [Fact]
    public void Missing_setting_throws_naming_the_key()
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => AppBaseUrl.FromConfiguration(ConfigWith(null)));

        // The message has to name the key: an operator reading a failed startup needs to know
        // what to set, not merely that something is wrong.
        Assert.Contains(AppBaseUrl.ConfigurationKey, error.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_setting_is_treated_as_missing(string value)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => AppBaseUrl.FromConfiguration(ConfigWith(value)));

        Assert.Contains(AppBaseUrl.ConfigurationKey, error.Message);
    }

    [Theory]
    [InlineData("/Account")]                 // relative - the failure the old code produced
    [InlineData("app.example.com")]          // no scheme
    [InlineData("ftp://app.example.com")]    // absolute, wrong scheme
    [InlineData("file:///C:/inetpub")]       // absolute, wrong scheme
    public void Unusable_value_throws_and_quotes_what_was_configured(string value)
    {
        var error = Assert.Throws<InvalidOperationException>(
            () => AppBaseUrl.FromConfiguration(ConfigWith(value)));

        Assert.Contains(value, error.Message);
    }

    [Theory]
    [InlineData("https://app.example.com", "https://app.example.com/")]
    [InlineData("http://localhost:7299", "http://localhost:7299/")]
    [InlineData("https://example.com/portal", "https://example.com/portal/")]
    public void Valid_value_is_accepted_and_normalised(string configured, string expected)
    {
        var baseUrl = AppBaseUrl.FromConfiguration(ConfigWith(configured));

        Assert.Equal(expected, baseUrl.Value.AbsoluteUri);
    }

    [Fact]
    public void Null_configuration_is_rejected_by_argument_check_not_by_a_null_reference()
    {
        Assert.Throws<ArgumentNullException>(() => AppBaseUrl.FromConfiguration(null!));
    }
}
