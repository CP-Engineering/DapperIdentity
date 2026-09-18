using CPE.DapperIdentity.Jwt.Server;

namespace DapperIdentity.Tests;

/// <summary>
/// Pins the behaviour the per-email budget depends on.
/// </summary>
public class PasswordResetRateLimiterTests
{
    [Fact]
    public void Allows_the_permitted_number_then_refuses()
    {
        using var limiter = new PasswordResetRateLimiter(permitLimit: 3, window: TimeSpan.FromMinutes(15));

        Assert.True(limiter.TryAcquire("someone@example.com"));
        Assert.True(limiter.TryAcquire("someone@example.com"));
        Assert.True(limiter.TryAcquire("someone@example.com"));
        Assert.False(limiter.TryAcquire("someone@example.com"));
    }

    [Fact]
    public void Budgets_are_per_address()
    {
        // The whole reason for partitioning by email rather than by IP: one user exhausting
        // their attempts must not spend anyone else's.
        using var limiter = new PasswordResetRateLimiter(permitLimit: 1, window: TimeSpan.FromMinutes(15));

        Assert.True(limiter.TryAcquire("first@example.com"));
        Assert.False(limiter.TryAcquire("first@example.com"));
        Assert.True(limiter.TryAcquire("second@example.com"));
    }

    [Theory]
    [InlineData("Someone@Example.com")]
    [InlineData("  someone@example.com  ")]
    [InlineData("SOMEONE@EXAMPLE.COM")]
    public void Casing_and_whitespace_cannot_buy_extra_attempts(string variant)
    {
        using var limiter = new PasswordResetRateLimiter(permitLimit: 1, window: TimeSpan.FromMinutes(15));

        Assert.True(limiter.TryAcquire("someone@example.com"));
        Assert.False(limiter.TryAcquire(variant));
    }

    [Fact]
    public void A_missing_address_still_consumes_a_budget()
    {
        // The limiter runs before model state is trusted anywhere else, so it must not throw on
        // null - and all such requests sharing one partition is the right outcome.
        using var limiter = new PasswordResetRateLimiter(permitLimit: 1, window: TimeSpan.FromMinutes(15));

        Assert.True(limiter.TryAcquire(null));
        Assert.False(limiter.TryAcquire(null));
    }
}
