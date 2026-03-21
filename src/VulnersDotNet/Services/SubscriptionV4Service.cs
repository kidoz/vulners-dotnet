using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the V4 subscription service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class SubscriptionV4Service : BaseApiService, ISubscriptionV4Service
{
    public SubscriptionV4Service(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public Task<JsonElement> GetListAsync(CancellationToken cancellationToken = default)
    {
        return GetV4Async<JsonElement>("subscriptions/list/", cancellationToken);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<JsonElement> GetAsync(string id, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var url = $"subscriptions/get/?id={Uri.EscapeDataString(id)}";
        return GetV4Async<JsonElement>(url, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> CreateAsync(
        string name,
        Dictionary<string, object> query,
        Dictionary<string, object> delivery,
        string? licenseId = null,
        IEnumerable<string>? bulletinFields = null,
        bool isActive = true,
        string timestampSource = "modified",
        bool sendEmptyResult = false,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(delivery);
#else
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
        if (query == null)
            throw new ArgumentNullException(nameof(query));
        if (delivery == null)
            throw new ArgumentNullException(nameof(delivery));
#endif

        var request = new SubscriptionV4CreateRequest
        {
            Name = name,
            Query = query,
            Delivery = delivery,
            LicenseId = licenseId,
            BulletinFields = bulletinFields,
            IsActive = isActive,
            TimestampSource = timestampSource,
            SendEmptyResult = sendEmptyResult,
        };

        return PostV4Async<SubscriptionV4CreateRequest, JsonElement>(
            "subscriptions/create/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public Task<JsonElement> UpdateAsync(
        string id,
        string name,
        Dictionary<string, object> query,
        Dictionary<string, object> delivery,
        string? licenseId = null,
        IEnumerable<string>? bulletinFields = null,
        bool isActive = true,
        string timestampSource = "modified",
        bool sendEmptyResult = false,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(delivery);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
        if (query == null)
            throw new ArgumentNullException(nameof(query));
        if (delivery == null)
            throw new ArgumentNullException(nameof(delivery));
#endif

        var request = new SubscriptionV4UpdateRequest
        {
            Id = id,
            Name = name,
            Query = query,
            Delivery = delivery,
            LicenseId = licenseId,
            BulletinFields = bulletinFields,
            IsActive = isActive,
            TimestampSource = timestampSource,
            SendEmptyResult = sendEmptyResult,
        };

        return PutV4Async<SubscriptionV4UpdateRequest, JsonElement>(
            "subscriptions/update/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var url = $"subscriptions/delete/?id={Uri.EscapeDataString(id)}";
        return DeleteV4Async(url, cancellationToken);
    }
}
