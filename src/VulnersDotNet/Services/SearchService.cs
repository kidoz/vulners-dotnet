using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.RegularExpressions;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the search service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class SearchService : BaseApiService, ISearchService
{
    public SearchService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public Task<SearchResponseData> SearchAsync(
        string query,
        int limit = 100,
        int skip = 0,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        if (limit < 1 || limit > 10000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit),
                limit,
                "Limit must be between 1 and 10000."
            );
        }

        var request = new SearchRequest
        {
            Query = query,
            Size = limit,
            Skip = skip,
            Fields = fields,
        };

        return PostAsync<SearchRequest, SearchResponseData>(
            "search/lucene/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public async Task<SearchResponseData> SearchAllAsync(
        string query,
        int limit = 100,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        if (limit < 1)
        {
            throw new ArgumentOutOfRangeException(
                nameof(limit),
                limit,
                "Limit must be greater than 0."
            );
        }

        limit = Math.Min(limit, 10000);
        var fieldsList = fields as IReadOnlyList<string> ?? fields?.ToArray();

        var first = await SearchAsync(query, limit, 0, fieldsList, cancellationToken)
            .ConfigureAwait(false);

        var total = Math.Min(limit, first.Total);
        var maxChunkSize = first.MaxSearchSize;
        var documents = new List<SearchDocument>(first.Documents);
        var offset = documents.Count;

        while (offset < total && maxChunkSize > 0)
        {
            var chunkSize = Math.Min(maxChunkSize, total - offset);
            var chunk = await SearchAsync(query, chunkSize, offset, fieldsList, cancellationToken)
                .ConfigureAwait(false);
            documents.AddRange(chunk.Documents);
            if (chunk.Documents.Count < chunkSize)
            {
                break;
            }

            offset += chunk.Documents.Count;
        }

        return new SearchResponseData
        {
            Documents = documents,
            Total = first.Total,
            MaxSearchSize = maxChunkSize,
        };
    }

    /// <inheritdoc />
    public async Task<BulletinData> GetBulletinAsync(
        string id,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var request = new IdSearchRequest { Ids = new[] { id }, Fields = new[] { "*" } };

        var response = await PostAsync<IdSearchRequest, IdSearchResponseData>(
                "search/id/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.Documents.TryGetValue(id, out var bulletin))
        {
            throw new Exceptions.VulnersException($"Bulletin with ID '{id}' not found.");
        }

        return bulletin;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyDictionary<string, BulletinData>> GetMultipleBulletinsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(ids);
#else
        if (ids == null)
            throw new ArgumentNullException(nameof(ids));
#endif

        var request = new IdSearchRequest
        {
            Ids = ids,
            Fields = fields,
            References = false,
        };

        var response = await PostAsync<IdSearchRequest, IdSearchResponseData>(
                "search/id/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        return response.Documents;
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetBulletinReferencesAsync(
        string id,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var request = new IdSearchRequest
        {
            Ids = new[] { id },
            Fields = Array.Empty<string>(),
            References = true,
        };

        var response = await PostAsync<IdSearchRequest, JsonElement>(
                "search/id/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        if (response.TryGetProperty("references", out var references))
        {
            return references;
        }

        return response;
    }

    /// <inheritdoc />
    public async Task<JsonElement> GetMultipleBulletinReferencesAsync(
        IEnumerable<string> ids,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(ids);
#else
        if (ids == null)
            throw new ArgumentNullException(nameof(ids));
#endif

        var request = new IdSearchRequest
        {
            Ids = ids,
            Fields = Array.Empty<string>(),
            References = true,
        };

        var response = await PostAsync<IdSearchRequest, JsonElement>(
                "search/id/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        if (response.TryGetProperty("references", out var references))
        {
            return references;
        }

        return response;
    }

    /// <inheritdoc />
    public Task<JsonElement> GetBulletinWithReferencesAsync(
        string id,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        return GetMultipleBulletinsWithReferencesAsync(new[] { id }, fields, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> GetMultipleBulletinsWithReferencesAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(ids);
#else
        if (ids == null)
            throw new ArgumentNullException(nameof(ids));
#endif

        var request = new IdSearchRequest
        {
            Ids = ids,
            Fields = fields,
            References = true,
        };

        return PostAsync<IdSearchRequest, JsonElement>("search/id/", request, cancellationToken);
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public async Task<JsonElement> GetBulletinHistoryAsync(
        string id,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(id);
#else
        if (string.IsNullOrEmpty(id))
            throw new ArgumentException("Value cannot be null or empty.", nameof(id));
#endif

        var url = $"search/history/?id={Uri.EscapeDataString(id)}";
        var response = await GetAsync<BulletinHistoryResponseData>(url, cancellationToken)
            .ConfigureAwait(false);
        return response.Result;
    }

    /// <inheritdoc />
    public Task<SearchResponseData> SearchExploitsAsync(
        string query,
        IEnumerable<string>? lookupFields = null,
        int limit = 20,
        int skip = 0,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        return SearchAsync(
            BuildExploitQuery(query, lookupFields),
            limit,
            skip,
            fields,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public Task<SearchResponseData> SearchExploitsAllAsync(
        string query,
        IEnumerable<string>? lookupFields = null,
        int limit = 100,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        return SearchAllAsync(
            BuildExploitQuery(query, lookupFields),
            limit,
            fields,
            cancellationToken
        );
    }

    /// <summary>
    /// Builds a Lucene exploit query, quoting bare CVE IDs and optionally restricting
    /// the search to a set of lookup fields — mirrors the Python reference SDK.
    /// </summary>
    private static string BuildExploitQuery(string query, IEnumerable<string>? lookupFields)
    {
        var trimmed = query.Trim();
        if (Regex.IsMatch(trimmed, @"^CVE-\d{4}-\d+$", RegexOptions.IgnoreCase))
        {
            trimmed = $"\"{trimmed}\"";
        }

        var fieldsList = lookupFields as IList<string> ?? lookupFields?.ToList();
        if (fieldsList != null && fieldsList.Count > 0)
        {
            var fieldQueries = string.Join(" OR ", fieldsList.Select(f => $"{f}:\"{trimmed}\""));
            return $"bulletinFamily:exploit AND ({fieldQueries})";
        }

        return $"bulletinFamily:exploit AND ({trimmed})";
    }

    /// <inheritdoc />
    public async Task<KbSeedsResult> GetKbSeedsAsync(
        string kbId,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(kbId);
#else
        if (string.IsNullOrEmpty(kbId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(kbId));
#endif

        var request = new IdSearchRequest
        {
            Ids = new[] { kbId },
            Fields = new[] { "superseeds", "parentseeds" },
        };

        var response = await PostAsync<IdSearchRequest, IdSearchResponseData>(
                "search/id/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        if (!response.Documents.TryGetValue(kbId, out var bulletin))
        {
            return new KbSeedsResult();
        }

        var superseeds = Array.Empty<string>();
        var parentseeds = Array.Empty<string>();

        if (bulletin.AdditionalFields != null)
        {
            if (bulletin.AdditionalFields.TryGetValue("superseeds", out var ss))
            {
                superseeds = ss.Deserialize<string[]>() ?? Array.Empty<string>();
            }

            if (bulletin.AdditionalFields.TryGetValue("parentseeds", out var ps))
            {
                parentseeds = ps.Deserialize<string[]>() ?? Array.Empty<string>();
            }
        }

        return new KbSeedsResult { Superseeds = superseeds, Parentseeds = parentseeds };
    }

    /// <inheritdoc />
    public Task<SearchResponseData> GetKbUpdatesAsync(
        string kbId,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(kbId);
#else
        if (string.IsNullOrEmpty(kbId))
            throw new ArgumentException("Value cannot be null or empty.", nameof(kbId));
#endif

        var query = $"type:msupdate AND kb:({kbId})";
        return SearchAsync(
            query,
            limit: 1000,
            fields: fields,
            cancellationToken: cancellationToken
        );
    }

    /// <inheritdoc />
    public Task<JsonElement> GetWebVulnsAsync(
        IEnumerable<string> paths,
        object? application = null,
        string match = "partial",
        IEnumerable<string>? config = null,
        string catalog = "official",
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(paths);
#else
        if (paths == null)
            throw new ArgumentNullException(nameof(paths));
#endif

        var request = new WebVulnsRequest
        {
            Paths = paths,
            Application = application,
            Match = match,
            Config = config,
            Catalog = catalog,
        };

        return PostV4Async<WebVulnsRequest, JsonElement>(
            "search/web-vulns/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> AutocompleteAsync(
        string query,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(query);
#else
        if (string.IsNullOrEmpty(query))
            throw new ArgumentException("Value cannot be null or empty.", nameof(query));
#endif

        var request = new AutocompleteRequest { Query = query };
        var response = await PostAsync<AutocompleteRequest, AutocompleteResponseData>(
                "search/autocomplete/",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);

        var results = new List<string>();
        foreach (var suggestion in response.Suggestions)
        {
            if (suggestion.ValueKind == JsonValueKind.Array && suggestion.GetArrayLength() > 0)
            {
                var text = suggestion[0].GetString();
                if (text is not null)
                {
                    results.Add(text);
                }
            }
        }

        return results;
    }

    /// <inheritdoc />
    [SuppressMessage(
        "Design",
        "CA1054:URI-like parameters should not be strings",
        Justification = "Building query string URL"
    )]
    public Task<CpeSearchResponseData> SearchCpeAsync(
        string product,
        string? vendor = null,
        int? size = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(product);
#else
        if (string.IsNullOrEmpty(product))
            throw new ArgumentException("Value cannot be null or empty.", nameof(product));
#endif

        if (size is < 0 or > 10000)
        {
            throw new ArgumentOutOfRangeException(
                nameof(size),
                size,
                "Size must be between 0 and 10000."
            );
        }

        var url = $"search/cpe?product={Uri.EscapeDataString(product)}";
        if (!string.IsNullOrEmpty(vendor))
        {
            url += $"&vendor={Uri.EscapeDataString(vendor)}";
        }

        if (size.HasValue)
        {
            url += $"&size={size.Value}";
        }

        return GetV4Async<CpeSearchResponseData>(url, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> SearchCpeMatchAsync(
        IEnumerable<string> software,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(software);
#else
        if (software == null)
            throw new ArgumentNullException(nameof(software));
#endif

        var request = new CpeMatchRequest { Software = software };
        return PostV4Async<CpeMatchRequest, JsonElement>("search/cpe", request, cancellationToken);
    }
}
