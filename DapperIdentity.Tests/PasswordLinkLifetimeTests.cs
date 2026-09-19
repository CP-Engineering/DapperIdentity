using System;
using System.Collections.Generic;
using CPE.DapperIdentity.Jwt.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace DapperIdentity.Tests;

/// <summary>
/// Covers where the password-link lifetime comes from, how the sources layer, and the range every
/// source is held to.
/// </summary>
/// <remarks>
/// The emails tell recipients how long their link lasts, and read that from the same option the
/// token provider enforces. These tests pin the three ways that option can be set - the library
/// default, the configuration key, a consumer's own Configure call - and that the 15-minute to
/// 24-hour range applies to all three rather than only to the one a check happened to sit on.
/// </remarks>
public class PasswordLinkLifetimeTests
{
    /// <summary>Everything AddJwtIdentity requires, plus an optional lifetime.</summary>
    private static IConfiguration Config(string? lifetime = null)
    {
        var values = new Dictionary<string, string?>
        {
            [AppBaseUrl.ConfigurationKey] = "https://app.example.test",
            ["JwtTokenSettings:ValidIssuer"] = "test-issuer",
            ["JwtTokenSettings:ValidAudience"] = "test-audience",
            ["JwtTokenSettings:SymmetricSecurityKey"] = "a-test-signing-key-that-is-long-enough-for-hmac",
            ["JwtTokenSettings:JwtExpireSeconds"] = "900",
            ["JwtTokenSettings:RefreshTokenLifeDays"] = "4",
        };
        if (lifetime is not null) values[DapperIdentityDefaults.PasswordLinkLifetimeConfigurationKey] = lifetime;

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    private static ServiceCollection Registered(IConfiguration configuration)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJwtIdentity(configuration);
        return services;
    }

    private static TimeSpan EffectiveLifetime(ServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<DataProtectionTokenProviderOptions>>().Value.TokenLifespan;
    }

    [Fact]
    public void The_library_configures_the_default_itself_rather_than_inheriting_it()
    {
        using var provider = Registered(Config()).BuildServiceProvider();

        // Reading the resolved option would prove nothing here: the framework's own default is one
        // day, which equals the 24 hours configured, so deleting the library's Configure call would
        // still produce the right answer. That was checked, and it did. Instead start from a value
        // nobody would choose and run the registered configurers over it - the library's must
        // overwrite it.
        var sentinel = new DataProtectionTokenProviderOptions { TokenLifespan = TimeSpan.FromMinutes(7) };
        foreach (var configure in provider.GetServices<IConfigureOptions<DataProtectionTokenProviderOptions>>())
        {
            configure.Configure(sentinel);
        }

        Assert.Equal(DapperIdentityDefaults.PasswordLinkLifetime, sentinel.TokenLifespan);
    }

    [Fact]
    public void The_configuration_key_replaces_the_default()
    {
        Assert.Equal(TimeSpan.FromHours(1), EffectiveLifetime(Registered(Config("01:00:00"))));
    }

    [Fact]
    public void A_consumer_Configure_call_after_registration_wins_over_both()
    {
        // The layering that matters: the library default, then the configuration key, then the
        // consumer's own code, each applied after the last.
        var services = Registered(Config("01:00:00"));
        services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromMinutes(30));

        Assert.Equal(TimeSpan.FromMinutes(30), EffectiveLifetime(services));
    }

    [Theory]
    [InlineData("2.00:00:00")]   // two days - above the ceiling
    [InlineData("1.00:00:01")]   // one second over
    [InlineData("00:05:00")]     // below the floor
    [InlineData("00:14:59")]     // one second under
    public void An_out_of_range_configuration_value_is_refused(string lifetime)
    {
        var services = Registered(Config(lifetime));

        Assert.Throws<OptionsValidationException>(() => EffectiveLifetime(services));
    }

    [Fact]
    public void An_out_of_range_value_set_in_code_is_refused_as_well()
    {
        // The reason the check sits on the option and not on the configuration key: a check made
        // only while reading appsettings would never see this.
        var services = Registered(Config());
        services.Configure<DataProtectionTokenProviderOptions>(o => o.TokenLifespan = TimeSpan.FromDays(30));

        Assert.Throws<OptionsValidationException>(() => EffectiveLifetime(services));
    }

    [Theory]
    [InlineData("00:15:00")]
    [InlineData("1.00:00:00")]
    public void The_boundaries_themselves_are_permitted(string lifetime)
    {
        var expected = TimeSpan.Parse(lifetime, System.Globalization.CultureInfo.InvariantCulture);

        Assert.Equal(expected, EffectiveLifetime(Registered(Config(lifetime))));
    }

    [Fact]
    public void An_unparseable_configuration_value_fails_naming_the_key()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Registered(Config("a day or so")));

        Assert.Contains(DapperIdentityDefaults.PasswordLinkLifetimeConfigurationKey, error.Message);
    }

    [Theory]
    [InlineData(24 * 60, "24 hours")]
    [InlineData(60, "1 hour")]
    [InlineData(120, "2 hours")]
    [InlineData(90, "90 minutes")]
    [InlineData(15, "15 minutes")]
    public void Describe_reads_as_the_end_of_a_sentence(int minutes, string expected)
    {
        // Quoted into "This link expires in {..}", so it has to read naturally there.
        Assert.Equal(expected, DapperIdentityDefaults.Describe(TimeSpan.FromMinutes(minutes)));
    }
}
