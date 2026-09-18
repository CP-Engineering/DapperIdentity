namespace CPE.DapperIdentity.Abstractions
{
    /// <summary>
    /// Supplies the host application's own name to the library.
    /// </summary>
    /// <remarks>
    /// The consumer implements this and registers it with <c>AddIAppSettings</c>. The JWT
    /// controller reads <see cref="ApplicationName"/> into the subject and body of the
    /// registration and password-reset emails, so the recipient sees which application wrote to
    /// them rather than an anonymous message with a link in it.
    /// </remarks>
    public interface IAppSettings
    {
        /// <summary>
        /// The application's name as a user should see it, for example in an email subject line.
        /// </summary>
        string ApplicationName { get; }
    }
}
