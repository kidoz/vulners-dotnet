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

    private string _baseUrl = "https://vulners.com/api/v3/";

    /// <summary>
    /// Gets or sets the base URL for the Vulners V3 API. Defaults to the official API.
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

    private string? _v4BaseUrl;

    /// <summary>
    /// Gets or sets the base URL for the Vulners V4 API.
    /// Defaults to the V4 sibling of <see cref="BaseUrl"/> (replaces /v3/ with /v4/).
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
        get => _v4BaseUrl ?? DeriveV4Url(_baseUrl);
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
        // If V4BaseUrl was not explicitly set and derivation is a no-op
        // (BaseUrl doesn't contain /v3/), the V4 calls would go to the wrong endpoint.
        if (
            _v4BaseUrl == null
#if NET8_0_OR_GREATER
            && string.Equals(_baseUrl, DeriveV4Url(_baseUrl), StringComparison.Ordinal)
#else
            && _baseUrl == DeriveV4Url(_baseUrl)
#endif
        )
        {
            throw new InvalidOperationException(
                $"Cannot derive V4 API URL from BaseUrl '{_baseUrl}' — no '/v3/' segment found. "
                    + "Set VulnersOptions.V4BaseUrl explicitly when using a non-standard URL layout."
            );
        }
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

        if (!Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            throw new ArgumentException(
                $"'{url}' is not a valid absolute URL.",
                nameof(url)
            );
        }

        return url;
    }

    private static string DeriveV4Url(string baseUrl)
    {
#if NET8_0_OR_GREATER
        return baseUrl.Replace("/v3/", "/v4/", StringComparison.Ordinal);
#else
        return baseUrl.Replace("/v3/", "/v4/");
#endif
    }
}
