using System.Diagnostics.CodeAnalysis;

namespace VulnersDotNet;

/// <summary>
/// Configuration options for the Vulners API client.
/// </summary>
public class VulnersOptions
{
    /// <summary>
    /// Gets or sets the API key used for authenticating with the Vulners API.
    /// You can obtain an API key from your Vulners user profile.
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;

    private string _baseUrl = "https://vulners.com/api/";

    /// <summary>
    /// Gets or sets the version-agnostic base URL for the Vulners API (the common
    /// root shared by the V3 and V4 surfaces). Defaults to <c>https://vulners.com/api/</c>.
    /// The <c>v3/</c> and <c>v4/</c> segments are appended automatically to form
    /// <see cref="V3BaseUrl"/> and <see cref="V4BaseUrl"/>.
    /// A trailing slash is added automatically if missing.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1056:URI-like properties should not be strings",
        Justification = "Strings are preferred for options configuration"
    )]
    public string BaseUrl
    {
        get => _baseUrl;
        set => _baseUrl = NormalizeUrl(value);
    }

    private string? _v3BaseUrl;

    /// <summary>
    /// Gets or sets the base URL for the Vulners V3 API.
    /// Defaults to the <c>v3/</c> sibling of <see cref="BaseUrl"/>.
    /// Set explicitly when using a proxy or non-standard URL layout.
    /// A trailing slash is added automatically if missing.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1056:URI-like properties should not be strings",
        Justification = "Strings are preferred for options configuration"
    )]
    public string V3BaseUrl
    {
        get => _v3BaseUrl ?? DeriveVersionUrl(_baseUrl, "v3");
        set => _v3BaseUrl = NormalizeUrl(value);
    }

    private string? _v4BaseUrl;

    /// <summary>
    /// Gets or sets the base URL for the Vulners V4 API.
    /// Defaults to the <c>v4/</c> sibling of <see cref="BaseUrl"/>.
    /// Set explicitly when using a proxy or non-standard URL layout.
    /// A trailing slash is added automatically if missing.
    /// </summary>
    [SuppressMessage(
        "Design",
        "CA1056:URI-like properties should not be strings",
        Justification = "Strings are preferred for options configuration"
    )]
    public string V4BaseUrl
    {
        get => _v4BaseUrl ?? DeriveVersionUrl(_baseUrl, "v4");
        set => _v4BaseUrl = NormalizeUrl(value);
    }

    /// <summary>
    /// Gets or sets the default timeout for API requests. Defaults to 30 seconds.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Validates the configured options and throws if the configuration is invalid.
    /// Called automatically by <c>AddVulners</c>.
    /// </summary>
    internal void Validate()
    {
        // Accessing the derived URLs forces normalization/validation of the
        // effective V3 and V4 endpoints and surfaces any misconfiguration early.
        _ = V3BaseUrl;
        _ = V4BaseUrl;
    }

    private static string NormalizeUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            throw new ArgumentException("URL cannot be null or empty.", nameof(url));
        }

        url = url.Trim();

#if NET8_0_OR_GREATER
        if (!url.EndsWith('/'))
            url += "/";
#else
        if (!url.EndsWith("/", StringComparison.Ordinal))
            url += "/";
#endif

        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed))
        {
            throw new ArgumentException($"'{url}' is not a valid absolute URL.", nameof(url));
        }

        // The API key is attached to every outbound request, so require HTTPS to keep it
        // in transit-encrypted channels. Plain HTTP is allowed only for loopback hosts
        // (localhost / 127.0.0.1 / ::1) to support local testing and mock servers.
        if (
            !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && !parsed.IsLoopback
        )
        {
            throw new ArgumentException(
                $"'{url}' must use HTTPS. Plain HTTP is only permitted for loopback hosts.",
                nameof(url)
            );
        }

        return url;
    }

    // baseUrl is guaranteed by NormalizeUrl to end with a trailing slash.
    private static string DeriveVersionUrl(string baseUrl, string version) =>
        baseUrl + version + "/";
}
