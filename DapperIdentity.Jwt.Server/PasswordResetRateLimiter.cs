using System;
using System.Threading.RateLimiting;

namespace CPE.DapperIdentity.Jwt.Server;

/// <summary>
/// Caps how often a password reset can be requested or completed for one email address.
/// </summary>
/// <remarks>
/// <para>
/// Partitioned by email address rather than by caller IP, deliberately. A clinic behind one NAT
/// address shares an IP, so an IP partition would let one user's activity lock out everyone
/// sitting beside them; and an attacker rotating addresses would slip an IP limit anyway. The
/// thing being protected is an account, so the account is what the budget belongs to.
/// </para>
/// <para>
/// Applied before the account is looked up and regardless of whether it exists, so a caller
/// cannot tell a registered address from an unregistered one by watching for a 429.
/// </para>
/// <para>
/// Partitions are held in memory, so the budget is per process: two instances behind a load
/// balancer give an attacker two budgets. <see cref="PartitionedRateLimiter"/> retires idle
/// partitions on its own, so submitting many distinct addresses does not grow memory without
/// bound.
/// </para>
/// </remarks>
public sealed class PasswordResetRateLimiter : IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    /// <summary>Creates the limiter.</summary>
    /// <param name="permitLimit">Requests allowed per address per window. Defaults to 5.</param>
    /// <param name="window">Length of the window. Defaults to 15 minutes.</param>
    public PasswordResetRateLimiter(int permitLimit = 5, TimeSpan? window = null)
    {
        var length = window ?? TimeSpan.FromMinutes(15);

        _limiter = PartitionedRateLimiter.Create<string, string>(email =>
            RateLimitPartition.GetFixedWindowLimiter(email, _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = length,
                QueueLimit = 0,          // Reject immediately; a queued reset request helps nobody.
                AutoReplenishment = true
            }));
    }

    /// <summary>Takes one permit for the address, if the budget allows.</summary>
    /// <param name="email">
    /// The address from the request, used as-is by the caller but normalised here so that
    /// casing and surrounding whitespace cannot be varied to win extra attempts.
    /// </param>
    /// <returns>True when the request may proceed; false when the budget is spent.</returns>
    public bool TryAcquire(string? email)
    {
        var partition = (email ?? string.Empty).Trim().ToUpperInvariant();
        using var lease = _limiter.AttemptAcquire(partition);
        return lease.IsAcquired;
    }

    /// <summary>Releases the underlying partitions.</summary>
    public void Dispose() => _limiter.Dispose();
}
