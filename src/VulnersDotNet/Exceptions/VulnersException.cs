using System.Net;

namespace VulnersDotNet.Exceptions;

/// <summary>
/// Represents an error returned by the Vulners API or the SDK itself.
/// </summary>
public class VulnersException : Exception
{
    /// <summary>
    /// Gets the HTTP status code associated with the error, if applicable.
    /// </summary>
    public HttpStatusCode? StatusCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="VulnersException"/> class.
    /// </summary>
    public VulnersException() { }

    /// <summary>
    /// Initializes a new instance of the <see cref="VulnersException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    public VulnersException(string message)
        : base(message) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="VulnersException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="statusCode">The HTTP status code.</param>
    public VulnersException(string message, HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="VulnersException"/> class.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception that caused this exception.</param>
    public VulnersException(string message, Exception innerException)
        : base(message, innerException) { }
}
