using System.Diagnostics.CodeAnalysis;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the archive/collection service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class ArchiveService : BaseApiService, IArchiveService
{
    public ArchiveService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<Stream> DownloadDistributiveAsync(
        string os,
        string version,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(os);
        ArgumentException.ThrowIfNullOrEmpty(version);
#else
        if (string.IsNullOrEmpty(os))
            throw new ArgumentException("Value cannot be null or empty.", nameof(os));
        if (string.IsNullOrEmpty(version))
            throw new ArgumentException("Value cannot be null or empty.", nameof(version));
#endif

        var url =
            $"archive/distributive?os={Uri.EscapeDataString(os)}&version={Uri.EscapeDataString(version)}";
        return GetStreamAsync(url, cancellationToken);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<IReadOnlyList<CollectionEntry>> GetCollectionAsync(
        string type,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(type);
#else
        if (string.IsNullOrEmpty(type))
            throw new ArgumentException("Value cannot be null or empty.", nameof(type));
#endif

        var url = $"archive/collection?type={Uri.EscapeDataString(type)}";
        return await GetV4GzipJsonAsync<List<CollectionEntry>>(url, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<IReadOnlyList<CollectionEntry>> GetCollectionUpdateAsync(
        string type,
        DateTimeOffset after,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(type);
#else
        if (string.IsNullOrEmpty(type))
            throw new ArgumentException("Value cannot be null or empty.", nameof(type));
#endif

        var afterStr = FormatAfter(after);
        var url =
            $"archive/collection-update?type={Uri.EscapeDataString(type)}&after={Uri.EscapeDataString(afterStr)}";
        return await GetV4GzipJsonAsync<List<CollectionEntry>>(url, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<ArchiveState> GetCollectionStateAsync(
        string type,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(type);
#else
        if (string.IsNullOrEmpty(type))
            throw new ArgumentException("Value cannot be null or empty.", nameof(type));
#endif

        var url = $"archive/collection-state?type={Uri.EscapeDataString(type)}";
        return GetV4Async<ArchiveState>(url, cancellationToken);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<IReadOnlyList<CollectionEntry>> GetFamilyAsync(
        string name,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(name);
#else
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
#endif

        var url = $"archive/family?name={Uri.EscapeDataString(name)}";
        return await GetV4GzipJsonAsync<List<CollectionEntry>>(url, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<IReadOnlyList<CollectionEntry>> GetFamilyUpdateAsync(
        string name,
        DateTimeOffset after,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(name);
#else
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
#endif

        var afterStr = FormatAfter(after);
        var url =
            $"archive/family-update?name={Uri.EscapeDataString(name)}&after={Uri.EscapeDataString(afterStr)}";
        return await GetV4GzipJsonAsync<List<CollectionEntry>>(url, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<ArchiveState> GetFamilyStateAsync(
        string name,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(name);
#else
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
#endif

        var url = $"archive/family-state?name={Uri.EscapeDataString(name)}";
        return GetV4Async<ArchiveState>(url, cancellationToken);
    }

    /// <summary>
    /// Validates an incremental-update timestamp (must be within the last 25 hours and
    /// not in the future) and formats it as the API's expected UTC string.
    /// </summary>
    private static string FormatAfter(DateTimeOffset after)
    {
        var now = DateTimeOffset.UtcNow;
        if (after > now)
        {
            throw new ArgumentOutOfRangeException(
                nameof(after),
                after,
                "The 'after' timestamp must not be in the future."
            );
        }

        if (now - after > TimeSpan.FromHours(25))
        {
            throw new ArgumentOutOfRangeException(
                nameof(after),
                after,
                "The 'after' timestamp must be within the last 25 hours."
            );
        }

        return after.UtcDateTime.ToString(
            "yyyy-MM-ddTHH:mm:ss",
            System.Globalization.CultureInfo.InvariantCulture
        );
    }
}
