using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the STIX service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class StixService : BaseApiService, IStixService
{
    public StixService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<JsonElement> MakeBundleByIdAsync(
        string id,
        string? openctiId = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var url = $"stix/bundle?id={Uri.EscapeDataString(id)}";
        if (!string.IsNullOrEmpty(openctiId))
        {
            url += $"&opencti_id={Uri.EscapeDataString(openctiId)}";
        }

        return GetV4Async<JsonElement>(url, cancellationToken);
    }
}
