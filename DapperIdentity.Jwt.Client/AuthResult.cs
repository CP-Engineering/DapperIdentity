using System;
using System.Diagnostics.CodeAnalysis;

namespace CPE.DapperIdentity.Jwt.Client;

/// <summary>
/// The outcome of an authentication attempt: either tokens, or a reason there are none.
/// </summary>
/// <remarks>
/// This replaces the old convention of returning an empty <c>AuthResponse</c> to mean failure,
/// which made every caller test a string to find out what happened and gave them no way to tell a
/// rejected password from an unreachable server. It maps the wire model rather than wrapping it,
/// so nothing downstream has to know the response shape.
/// </remarks>
public sealed class AuthResult
{
    private AuthResult(AuthTokens? tokens, AuthFailure failure)
    {
        Tokens = tokens;
        Failure = failure;
    }

    /// <summary>The tokens, when <see cref="Succeeded"/> is true; otherwise null.</summary>
    public AuthTokens? Tokens { get; }

    /// <summary>Why the attempt failed, or <see cref="AuthFailure.None"/> when it did not.</summary>
    public AuthFailure Failure { get; }

    /// <summary>True when tokens were obtained.</summary>
    /// <remarks>
    /// The attribute lets the compiler treat <see cref="Tokens"/> as non-null inside a
    /// <c>if (result.Succeeded)</c> branch, so callers do not need a second null check.
    /// </remarks>
    [MemberNotNullWhen(true, nameof(Tokens))]
    public bool Succeeded => Failure == AuthFailure.None;

    /// <summary>Creates a successful result.</summary>
    /// <param name="tokens">The tokens obtained.</param>
    /// <returns>A result whose <see cref="Succeeded"/> is true.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="tokens"/> is null.</exception>
    public static AuthResult Success(AuthTokens tokens)
    {
        if (tokens is null) throw new ArgumentNullException(nameof(tokens));
        return new AuthResult(tokens, AuthFailure.None);
    }

    /// <summary>Creates a failed result.</summary>
    /// <param name="failure">Why the attempt failed.</param>
    /// <returns>A result whose <see cref="Succeeded"/> is false.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="failure"/> is <see cref="AuthFailure.None"/>, which would produce a result
    /// claiming success with no tokens behind it.
    /// </exception>
    public static AuthResult Failed(AuthFailure failure)
    {
        if (failure == AuthFailure.None)
        {
            throw new ArgumentException(
                "A failed result needs a reason; AuthFailure.None means success.", nameof(failure));
        }
        return new AuthResult(null, failure);
    }
}
