using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VulnersDotNet.Models;

/// <summary>
/// Represents the data returned by a search query.
/// </summary>
public record SearchResponseData
{
    /// <summary>
    /// Gets the list of documents matching the search query.
    /// </summary>
    [JsonPropertyName("search")]
    public IReadOnlyList<SearchDocument> Documents { get; init; } = Array.Empty<SearchDocument>();

    /// <summary>
    /// Gets the total count of matches.
    /// </summary>
    [JsonPropertyName("total")]
    public int Total { get; init; }
}

/// <summary>
/// Represents a single search result document with Elasticsearch-style wrapper fields.
/// </summary>
public record SearchDocument
{
    /// <summary>
    /// Gets the unique identifier of the document.
    /// </summary>
    [JsonPropertyName("_id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Gets the index the document belongs to.
    /// </summary>
    [JsonPropertyName("_index")]
    public string Index { get; init; } = string.Empty;

    /// <summary>
    /// Gets the relevance score.
    /// </summary>
    [JsonPropertyName("_score")]
    public double Score { get; init; }

    /// <summary>
    /// Gets the underlying bulletin data.
    /// </summary>
    [JsonPropertyName("_source")]
    public BulletinData Source { get; init; } = new();

    /// <summary>
    /// Gets the flat description (truncated).
    /// </summary>
    [JsonPropertyName("flatDescription")]
    public string? FlatDescription { get; init; }
}

/// <summary>
/// Represents a bulletin or vulnerability document with flat fields.
/// Used both inside <see cref="SearchDocument.Source"/> and in <see cref="IdSearchResponseData"/> results.
/// </summary>
public record BulletinData
{
    /// <summary>
    /// Gets the unique identifier of the bulletin.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Gets the title of the bulletin.
    /// </summary>
    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    /// <summary>
    /// Gets the description of the bulletin.
    /// </summary>
    [JsonPropertyName("description")]
    public string Description { get; init; } = string.Empty;

    /// <summary>
    /// Gets the bulletin type (e.g., "cve", "exploitdb").
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    /// <summary>
    /// Gets the bulletin family (e.g., "cve", "exploit").
    /// </summary>
    [JsonPropertyName("bulletinFamily")]
    public string BulletinFamily { get; init; } = string.Empty;

    /// <summary>
    /// Gets the publication date.
    /// </summary>
    [JsonPropertyName("published")]
    public DateTimeOffset? Published { get; init; }

    /// <summary>
    /// Gets the last modification date.
    /// </summary>
    [JsonPropertyName("modified")]
    public DateTimeOffset? Modified { get; init; }

    /// <summary>
    /// Gets the URL to the bulletin source.
    /// </summary>
    [JsonPropertyName("href")]
    public string Href { get; init; } = string.Empty;

    /// <summary>
    /// Gets the CVSS score information.
    /// </summary>
    [JsonPropertyName("cvss")]
    public CvssScore? Cvss { get; init; }

    /// <summary>
    /// Gets the list of CVE identifiers.
    /// </summary>
    [JsonPropertyName("cvelist")]
    public IReadOnlyList<string> CveList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets any additional fields not explicitly modeled.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalFields { get; init; }
}

/// <summary>
/// Represents CVSS score information.
/// </summary>
public record CvssScore
{
    /// <summary>
    /// Gets the numeric CVSS score.
    /// </summary>
    [JsonPropertyName("score")]
    public double Score { get; init; }

    /// <summary>
    /// Gets the CVSS vector string.
    /// </summary>
    [JsonPropertyName("vector")]
    public string Vector { get; init; } = string.Empty;

    /// <summary>
    /// Gets the severity level (e.g., "CRITICAL", "HIGH", "MEDIUM").
    /// </summary>
    [JsonPropertyName("severity")]
    public string Severity { get; init; } = string.Empty;

    /// <summary>
    /// Gets the CVSS version (e.g., "3.1", "2.0").
    /// </summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;
}

/// <summary>
/// Represents the data returned by an audit operation.
/// </summary>
public record AuditResponseData
{
    /// <summary>
    /// Gets the list of discovered vulnerability bulletin IDs.
    /// </summary>
    [JsonPropertyName("vulnerabilities")]
    public IReadOnlyList<string> Vulnerabilities { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the packages with their associated advisories.
    /// Keyed by package identifier, then by bulletin ID, each containing a list of advisories.
    /// </summary>
    [JsonPropertyName("packages")]
    public Dictionary<
        string,
        Dictionary<string, IReadOnlyList<AuditAdvisory>>
    > Packages { get; init; } = new();

    /// <summary>
    /// Gets the reasons mapping packages to vulnerabilities.
    /// </summary>
    [JsonPropertyName("reasons")]
    public IReadOnlyList<AuditReason> Reasons { get; init; } = Array.Empty<AuditReason>();

    /// <summary>
    /// Gets the consolidated list of CVE identifiers across all vulnerabilities.
    /// </summary>
    [JsonPropertyName("cvelist")]
    public IReadOnlyList<string> CveList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the cumulative fix command to remediate all vulnerabilities.
    /// </summary>
    [JsonPropertyName("cumulativeFix")]
    public string? CumulativeFix { get; init; }

    /// <summary>
    /// Gets the overall CVSS score information for the audit.
    /// </summary>
    [JsonPropertyName("cvss")]
    public CvssScore? Cvss { get; init; }

    /// <summary>
    /// Gets the internal Vulners audit ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string? AuditId { get; init; }
}

/// <summary>
/// Represents an audit reason mapping a package to a vulnerability.
/// </summary>
public record AuditReason
{
    /// <summary>
    /// Gets the package name.
    /// </summary>
    [JsonPropertyName("package")]
    public string Package { get; init; } = string.Empty;

    /// <summary>
    /// Gets the specific vulnerability ID.
    /// </summary>
    [JsonPropertyName("bulletin")]
    public string Bulletin { get; init; } = string.Empty;
}

/// <summary>
/// Represents an advisory for a specific vulnerability affecting a package.
/// </summary>
public record AuditAdvisory
{
    /// <summary>
    /// Gets the package string.
    /// </summary>
    [JsonPropertyName("package")]
    public string Package { get; init; } = string.Empty;

    /// <summary>
    /// Gets the installed version of the package.
    /// </summary>
    [JsonPropertyName("providedVersion")]
    public string ProvidedVersion { get; init; } = string.Empty;

    /// <summary>
    /// Gets the version referenced in the bulletin.
    /// </summary>
    [JsonPropertyName("bulletinVersion")]
    public string BulletinVersion { get; init; } = string.Empty;

    /// <summary>
    /// Gets the full provided package string.
    /// </summary>
    [JsonPropertyName("providedPackage")]
    public string ProvidedPackage { get; init; } = string.Empty;

    /// <summary>
    /// Gets the full bulletin package string.
    /// </summary>
    [JsonPropertyName("bulletinPackage")]
    public string BulletinPackage { get; init; } = string.Empty;

    /// <summary>
    /// Gets the comparison operator (e.g., "lt").
    /// </summary>
    [JsonPropertyName("operator")]
    public string Operator { get; init; } = string.Empty;

    /// <summary>
    /// Gets the bulletin identifier.
    /// </summary>
    [JsonPropertyName("bulletinID")]
    public string BulletinId { get; init; } = string.Empty;

    /// <summary>
    /// Gets the list of CVE identifiers associated with this advisory.
    /// </summary>
    [JsonPropertyName("cvelist")]
    public IReadOnlyList<string> CveList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Gets the CVSS score information.
    /// </summary>
    [JsonPropertyName("cvss")]
    public CvssScore? Cvss { get; init; }

    /// <summary>
    /// Gets the fix command for this specific advisory.
    /// </summary>
    [JsonPropertyName("fix")]
    public string? Fix { get; init; }
}

/// <summary>
/// Request payload for search.
/// </summary>
public record SearchRequest
{
    /// <summary>
    /// Lucene query string.
    /// </summary>
    [JsonPropertyName("query")]
    public string Query { get; init; } = string.Empty;

    /// <summary>
    /// Maximum number of results.
    /// </summary>
    [JsonPropertyName("size")]
    public int Size { get; init; } = 10;

    /// <summary>
    /// Number of results to skip.
    /// </summary>
    [JsonPropertyName("skip")]
    public int Skip { get; init; } = 0;

    /// <summary>
    /// Optional list of fields to return. Defaults to title, short_description, type, href, published, modified, ai_score.
    /// </summary>
    [JsonPropertyName("fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Fields { get; init; }
}

/// <summary>
/// Request payload for searching by ID.
/// </summary>
public record IdSearchRequest
{
    /// <summary>
    /// List of bulletin IDs to retrieve (max 3).
    /// </summary>
    [JsonPropertyName("id")]
    public IEnumerable<string> Ids { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Fields to return. Use ["*"] for all fields.
    /// </summary>
    [JsonPropertyName("fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Fields { get; init; }

    /// <summary>
    /// If true, return a map of sourceType to bulletins.
    /// </summary>
    [JsonPropertyName("references")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? References { get; init; }
}

/// <summary>
/// Represents the data returned by an ID search query.
/// </summary>
public record IdSearchResponseData
{
    /// <summary>
    /// Gets the documents keyed by bulletin ID.
    /// </summary>
    [JsonPropertyName("documents")]
    public Dictionary<string, BulletinData> Documents { get; init; } = new();
}

/// <summary>
/// Request payload for audit.
/// </summary>
public record AuditRequest
{
    /// <summary>
    /// Operating system name.
    /// </summary>
    [JsonPropertyName("os")]
    public string OS { get; init; } = string.Empty;

    /// <summary>
    /// Operating system version.
    /// </summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    /// <summary>
    /// List of packages (format: "name version arch" for DEB, "name-version-release.arch" for RPM).
    /// </summary>
    [JsonPropertyName("package")]
    public IEnumerable<string> Packages { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Whether to include advisories still awaiting vendor status. Defaults to true.
    /// </summary>
    [JsonPropertyName("include_candidates")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? IncludeCandidates { get; init; }
}

// ===================== Autocomplete =====================

/// <summary>
/// Request payload for search autocomplete.
/// </summary>
public record AutocompleteRequest
{
    /// <summary>
    /// Lucene search fragment to complete.
    /// </summary>
    [JsonPropertyName("query")]
    public string Query { get; init; } = string.Empty;
}

// ===================== CPE Search =====================

/// <summary>
/// Response data for CPE search by vendor/product.
/// </summary>
public record CpeSearchResponseData
{
    /// <summary>
    /// Gets the best matching CPE string.
    /// </summary>
    [JsonPropertyName("best_match")]
    public string BestMatch { get; init; } = string.Empty;

    /// <summary>
    /// Gets additional CPE identifiers associated with the query.
    /// </summary>
    [JsonPropertyName("cpe")]
    public IReadOnlyList<string> Cpe { get; init; } = Array.Empty<string>();
}

// ===================== CPE Object =====================

/// <summary>
/// Decomposed CPE; any attributes may be omitted for partial match.
/// </summary>
public record CpeObject
{
    /// <summary>
    /// CPE part: "a" (application), "o" (OS), "h" (hardware).
    /// </summary>
    [JsonPropertyName("part")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Part { get; init; }

    /// <summary>
    /// Vendor name.
    /// </summary>
    [JsonPropertyName("vendor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Vendor { get; init; }

    /// <summary>
    /// Product name.
    /// </summary>
    [JsonPropertyName("product")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Product { get; init; }

    /// <summary>
    /// Product version.
    /// </summary>
    [JsonPropertyName("version")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Version { get; init; }

    /// <summary>
    /// Update / service-pack label.
    /// </summary>
    [JsonPropertyName("update")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Update { get; init; }

    /// <summary>
    /// UI or build language code.
    /// </summary>
    [JsonPropertyName("language")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Language { get; init; }

    /// <summary>
    /// Target hardware platform.
    /// </summary>
    [JsonPropertyName("target_hw")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetHw { get; init; }

    /// <summary>
    /// Target software platform.
    /// </summary>
    [JsonPropertyName("target_sw")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetSw { get; init; }

    /// <summary>
    /// Edition / distribution channel.
    /// </summary>
    [JsonPropertyName("edition")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Edition { get; init; }
}

// ===================== CPE Software Input =====================

/// <summary>
/// Represents a software identifier for audit operations.
/// Can be either a CPE string or a <see cref="CpeObject"/>.
/// Use implicit conversions from <see cref="string"/> or <see cref="CpeObject"/>.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1815:Override equals and operator equals on value types",
    Justification = "Used as a parameter wrapper, not for equality comparison"
)]
public readonly struct CpeSoftwareInput
{
    /// <summary>
    /// Gets the underlying value (either a <see cref="string"/> or a <see cref="CpeObject"/>).
    /// </summary>
    internal object Value { get; }

    /// <summary>
    /// Creates a <see cref="CpeSoftwareInput"/> from a CPE string.
    /// </summary>
    /// <param name="cpeString">The CPE string (e.g., "cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*").</param>
    public CpeSoftwareInput(string cpeString)
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(cpeString);
#else
        if (string.IsNullOrEmpty(cpeString))
            throw new ArgumentException(
                "CPE string cannot be null or empty.",
                nameof(cpeString)
            );
#endif
        Value = cpeString;
    }

    /// <summary>
    /// Creates a <see cref="CpeSoftwareInput"/> from a CPE object.
    /// </summary>
    /// <param name="cpeObject">The CPE object with decomposed attributes.</param>
    public CpeSoftwareInput(CpeObject cpeObject)
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(cpeObject);
        Value = cpeObject;
#else
        Value = cpeObject ?? throw new ArgumentNullException(nameof(cpeObject));
#endif
    }

    /// <summary>
    /// Creates a <see cref="CpeSoftwareInput"/> from a CPE string.
    /// Named alternative for the implicit conversion operator.
    /// </summary>
    public static CpeSoftwareInput FromString(string cpeString) => new(cpeString);

    /// <summary>
    /// Creates a <see cref="CpeSoftwareInput"/> from a <see cref="CpeObject"/>.
    /// Named alternative for the implicit conversion operator.
    /// </summary>
    public static CpeSoftwareInput FromCpeObject(CpeObject cpeObject) => new(cpeObject);

    /// <summary>
    /// Implicitly converts a CPE string to a <see cref="CpeSoftwareInput"/>.
    /// </summary>
    public static implicit operator CpeSoftwareInput(string cpeString) => new(cpeString);

    /// <summary>
    /// Implicitly converts a <see cref="CpeObject"/> to a <see cref="CpeSoftwareInput"/>.
    /// </summary>
    public static implicit operator CpeSoftwareInput(CpeObject cpeObject) => new(cpeObject);
}

// ===================== V4 Audit Software =====================

/// <summary>
/// Request payload for POST /api/v4/audit/software (batch CPE audit).
/// </summary>
public record AuditSoftwareRequest
{
    /// <summary>
    /// List of CPE strings or <see cref="CpeObject"/> instances to audit.
    /// </summary>
    [JsonPropertyName("software")]
    public IEnumerable<object> Software { get; init; } = Array.Empty<object>();

    /// <summary>
    /// Matching strictness: "partial" (default) or "full".
    /// </summary>
    [JsonPropertyName("match")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Match { get; init; }

    /// <summary>
    /// Optional list of fields to return.
    /// </summary>
    [JsonPropertyName("fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Fields { get; init; }

    /// <summary>
    /// Optional configuration flags.
    /// </summary>
    [JsonPropertyName("config")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Config { get; init; }

    /// <summary>
    /// Catalog to search: "official" (default) or "extended".
    /// </summary>
    [JsonPropertyName("catalog")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Catalog { get; init; }
}

// ===================== V4 Audit Host =====================

/// <summary>
/// Request payload for POST /api/v4/audit/host (host context audit).
/// </summary>
public record AuditHostRequest
{
    /// <summary>
    /// Software CPEs installed on the host (strings or <see cref="CpeObject"/>).
    /// </summary>
    [JsonPropertyName("software")]
    public IEnumerable<object> Software { get; init; } = Array.Empty<object>();

    /// <summary>
    /// Host OS (CPE string or <see cref="CpeObject"/>).
    /// </summary>
    [JsonPropertyName("operating_system")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? OperatingSystem { get; init; }

    /// <summary>
    /// Optional hardware platform CPE.
    /// </summary>
    [JsonPropertyName("hardware")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Hardware { get; init; }

    /// <summary>
    /// Optional parent application CPE (e.g., CMS).
    /// </summary>
    [JsonPropertyName("application")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Application { get; init; }

    /// <summary>
    /// Matching strictness: "partial" (default) or "full".
    /// </summary>
    [JsonPropertyName("match")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Match { get; init; }

    /// <summary>
    /// Optional list of fields to return.
    /// </summary>
    [JsonPropertyName("fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Fields { get; init; }

    /// <summary>
    /// Optional configuration flags.
    /// </summary>
    [JsonPropertyName("config")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Config { get; init; }

    /// <summary>
    /// Catalog to search: "official" (default) or "extended".
    /// </summary>
    [JsonPropertyName("catalog")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Catalog { get; init; }
}

// ===================== V4 Audit Result =====================

/// <summary>
/// Result block for a single software item in V4 audit responses.
/// </summary>
public record AuditSoftwareResult
{
    /// <summary>
    /// Original software CPE input.
    /// </summary>
    [JsonPropertyName("input")]
    public JsonElement? Input { get; init; }

    /// <summary>
    /// Canonical CPE used for matching.
    /// </summary>
    [JsonPropertyName("matched_criteria")]
    public string MatchedCriteria { get; init; } = string.Empty;

    /// <summary>
    /// Vulnerabilities relevant to the input item.
    /// </summary>
    [JsonPropertyName("vulnerabilities")]
    public IReadOnlyList<VulnerabilityEntry> Vulnerabilities { get; init; } =
        Array.Empty<VulnerabilityEntry>();
}

/// <summary>
/// Individual vulnerability entry returned by V4 audit calls.
/// </summary>
public record VulnerabilityEntry
{
    /// <summary>
    /// Vulnerability ID.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Vulnerability title.
    /// </summary>
    [JsonPropertyName("title")]
    public string Title { get; init; } = string.Empty;

    /// <summary>
    /// Short description.
    /// </summary>
    [JsonPropertyName("short_description")]
    public string ShortDescription { get; init; } = string.Empty;

    /// <summary>
    /// Gets any additional fields not explicitly modeled.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalFields { get; init; }
}

// ===================== Windows KB Audit =====================

/// <summary>
/// Request payload for POST /api/v3/audit/kb (Windows KB audit).
/// </summary>
public record WindowsKbAuditRequest
{
    /// <summary>
    /// Windows version string (e.g., "Windows Server 2016").
    /// </summary>
    [JsonPropertyName("os")]
    public string OS { get; init; } = string.Empty;

    /// <summary>
    /// List of installed KB identifiers.
    /// </summary>
    [JsonPropertyName("kbList")]
    public IEnumerable<string> KbList { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Response data for Windows KB audit.
/// </summary>
public record WindowsKbAuditResponseData
{
    /// <summary>
    /// KBs that should be installed on the host.
    /// </summary>
    [JsonPropertyName("kbMissed")]
    public IReadOnlyList<string> KbMissed { get; init; } = Array.Empty<string>();

    /// <summary>
    /// CVE IDs associated with the missing KBs.
    /// </summary>
    [JsonPropertyName("cvelist")]
    public IReadOnlyList<string> CveList { get; init; } = Array.Empty<string>();
}

// ===================== Windows WinAudit =====================

/// <summary>
/// One installed program with optional CPE-like attributes for Windows audit.
/// </summary>
public record WindowsSoftwareEntry
{
    /// <summary>
    /// Product / package name.
    /// </summary>
    [JsonPropertyName("software")]
    public string Software { get; init; } = string.Empty;

    /// <summary>
    /// Product version string.
    /// </summary>
    [JsonPropertyName("version")]
    public string Version { get; init; } = string.Empty;

    /// <summary>
    /// Edition / distribution channel.
    /// </summary>
    [JsonPropertyName("sw_edition")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SwEdition { get; init; }

    /// <summary>
    /// Target software (defaults to "windows").
    /// </summary>
    [JsonPropertyName("target_sw")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetSw { get; init; }

    /// <summary>
    /// Hardware platform.
    /// </summary>
    [JsonPropertyName("target_hw")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TargetHw { get; init; }

    /// <summary>
    /// Optional update / service-pack label.
    /// </summary>
    [JsonPropertyName("update")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Update { get; init; }

    /// <summary>
    /// UI or build language code.
    /// </summary>
    [JsonPropertyName("language")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Language { get; init; }
}

/// <summary>
/// Request payload for POST /api/v3/audit/winaudit (Windows KB + software audit).
/// </summary>
public record WindowsWinAuditRequest
{
    /// <summary>
    /// API key for authentication (required in the request body by this endpoint).
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Operating-system family (e.g., "windows").
    /// </summary>
    [JsonPropertyName("os")]
    public string OS { get; init; } = string.Empty;

    /// <summary>
    /// Build number or marketing version (e.g., "10.0.19045").
    /// </summary>
    [JsonPropertyName("os_version")]
    public string OsVersion { get; init; } = string.Empty;

    /// <summary>
    /// List of installed KB identifiers.
    /// </summary>
    [JsonPropertyName("kb_list")]
    public IEnumerable<string> KbList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Installed programs with version info.
    /// </summary>
    [JsonPropertyName("software")]
    public IEnumerable<WindowsSoftwareEntry> Software { get; init; } =
        Array.Empty<WindowsSoftwareEntry>();

    /// <summary>
    /// Sets target_hw for every software entry (e.g., "arm64").
    /// </summary>
    [JsonPropertyName("platform")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Platform { get; init; }
}

/// <summary>
/// Missing patch/KB and its vulnerability details from Windows audit.
/// </summary>
public record WindowsAuditBulletin
{
    /// <summary>
    /// Affected package or OS line.
    /// </summary>
    [JsonPropertyName("package")]
    public string Package { get; init; } = string.Empty;

    /// <summary>
    /// Bulletin publish date.
    /// </summary>
    [JsonPropertyName("published")]
    public string? Published { get; init; }

    /// <summary>
    /// Vulners bulletin identifier.
    /// </summary>
    [JsonPropertyName("bulletinID")]
    public string BulletinId { get; init; } = string.Empty;

    /// <summary>
    /// CVE IDs linked to the bulletin.
    /// </summary>
    [JsonPropertyName("cvelist")]
    public IReadOnlyList<string> CveList { get; init; } = Array.Empty<string>();

    /// <summary>
    /// CVSS score object.
    /// </summary>
    [JsonPropertyName("cvss")]
    public CvssScore? Cvss { get; init; }

    /// <summary>
    /// Recommended patch / KB to apply.
    /// </summary>
    [JsonPropertyName("fix")]
    public string? Fix { get; init; }
}

// ===================== Supported OS =====================

/// <summary>
/// Response data for supported OS list.
/// </summary>
public record SupportedOsResponseData
{
    /// <summary>
    /// OS identifiers mapped to their package listing commands.
    /// </summary>
    [JsonPropertyName("supportedOS")]
    public Dictionary<string, string> SupportedOs { get; init; } = new();
}

/// <summary>
/// Response data for search autocomplete.
/// </summary>
public record AutocompleteResponseData
{
    /// <summary>
    /// Suggestions as [query_string, is_exact] pairs.
    /// </summary>
    [JsonPropertyName("suggestions")]
    public IReadOnlyList<JsonElement> Suggestions { get; init; } = Array.Empty<JsonElement>();
}

// ===================== Collection =====================

/// <summary>
/// One record from a CDN-cached collection archive.
/// </summary>
public record CollectionEntry
{
    /// <summary>
    /// Record identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Gets any additional fields (collection-specific).
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalFields { get; init; }
}

// ===================== Subscriptions =====================

/// <summary>
/// Request payload for listing email subscriptions.
/// </summary>
public record ListEmailSubscriptionRequest
{
    /// <summary>
    /// API key for authentication (required in the request body).
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }
}

/// <summary>
/// Response wrapper for the list email subscriptions endpoint.
/// </summary>
public record SubscriptionListResponseData
{
    /// <summary>
    /// Gets the list of email subscriptions.
    /// </summary>
    [JsonPropertyName("subscriptions")]
    public IReadOnlyList<EmailSubscription> Subscriptions { get; init; } =
        Array.Empty<EmailSubscription>();
}

/// <summary>
/// Represents an email subscription.
/// </summary>
public record EmailSubscription
{
    /// <summary>
    /// Gets the subscription identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Gets any additional fields not explicitly modeled.
    /// </summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? AdditionalFields { get; init; }
}

/// <summary>
/// Request payload for adding an email subscription.
/// </summary>
public record AddEmailSubscriptionRequest
{
    /// <summary>
    /// API key for authentication (required in the request body).
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Lucene search query for the subscription.
    /// </summary>
    [JsonPropertyName("query")]
    public string Query { get; init; } = string.Empty;

    /// <summary>
    /// Email address to send notifications to.
    /// </summary>
    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    /// <summary>
    /// Report format: "html", "json", or "pdf". Defaults to "html".
    /// </summary>
    [JsonPropertyName("format")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Format { get; init; }

    /// <summary>
    /// Cron expression for the schedule.
    /// </summary>
    [JsonPropertyName("crontab")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Crontab { get; init; }

    /// <summary>
    /// Query type. Defaults to "lucene".
    /// </summary>
    [JsonPropertyName("query_type")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? QueryType { get; init; }
}

/// <summary>
/// Request payload for editing an email subscription.
/// </summary>
public record EditEmailSubscriptionRequest
{
    /// <summary>
    /// API key for authentication (required in the request body).
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Subscription identifier to edit.
    /// </summary>
    [JsonPropertyName("subscriptionid")]
    public string SubscriptionId { get; init; } = string.Empty;

    /// <summary>
    /// Report format: "html", "json", or "pdf".
    /// </summary>
    [JsonPropertyName("format")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Format { get; init; }

    /// <summary>
    /// Cron expression for the schedule.
    /// </summary>
    [JsonPropertyName("crontab")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Crontab { get; init; }

    /// <summary>
    /// Whether the subscription is active: "yes", "no", "true", or "false".
    /// </summary>
    [JsonPropertyName("active")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Active { get; init; }
}

/// <summary>
/// Request payload for removing an email subscription.
/// </summary>
public record RemoveEmailSubscriptionRequest
{
    /// <summary>
    /// API key for authentication (required in the request body).
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Subscription identifier to remove.
    /// </summary>
    [JsonPropertyName("subscriptionid")]
    public string SubscriptionId { get; init; } = string.Empty;
}

// ===================== Web Vulns (V4) =====================

/// <summary>
/// Request payload for POST /api/v4/search/web-vulns/.
/// </summary>
public record WebVulnsRequest
{
    /// <summary>
    /// URL paths to check.
    /// </summary>
    [JsonPropertyName("paths")]
    public IEnumerable<string> Paths { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Application filter (string or object).
    /// </summary>
    [JsonPropertyName("application")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? Application { get; init; }

    /// <summary>
    /// Match mode: "partial" (default) or "full".
    /// </summary>
    [JsonPropertyName("match")]
    public string Match { get; init; } = "partial";

    /// <summary>
    /// Optional configuration flags.
    /// </summary>
    [JsonPropertyName("config")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Config { get; init; }

    /// <summary>
    /// Catalog: "official" (default) or "extended".
    /// </summary>
    [JsonPropertyName("catalog")]
    public string Catalog { get; init; } = "official";
}

// ===================== Bulletin History =====================

/// <summary>
/// Response wrapper for bulletin history.
/// </summary>
public record BulletinHistoryResponseData
{
    /// <summary>
    /// History entries.
    /// </summary>
    [JsonPropertyName("result")]
    public JsonElement Result { get; init; }
}

// ===================== KB Seeds =====================

/// <summary>
/// Result of KB seeds lookup.
/// </summary>
public record KbSeedsResult
{
    /// <summary>
    /// KBs covered by the queried KB.
    /// </summary>
    [JsonPropertyName("superseeds")]
    public IReadOnlyList<string> Superseeds { get; init; } = Array.Empty<string>();

    /// <summary>
    /// KBs that cover the queried KB.
    /// </summary>
    [JsonPropertyName("parentseeds")]
    public IReadOnlyList<string> Parentseeds { get; init; } = Array.Empty<string>();
}

// ===================== Linux Audit (V4) =====================

/// <summary>
/// Request payload for POST /api/v4/audit/linux.
/// </summary>
public record LinuxAuditRequest
{
    /// <summary>
    /// OS name or ID (e.g., "ubuntu", "debian", "rhel").
    /// </summary>
    [JsonPropertyName("osName")]
    public string OsName { get; init; } = string.Empty;

    /// <summary>
    /// OS version.
    /// </summary>
    [JsonPropertyName("osVersion")]
    public string OsVersion { get; init; } = string.Empty;

    /// <summary>
    /// Installed packages (max 2500).
    /// </summary>
    [JsonPropertyName("packages")]
    public IEnumerable<string> Packages { get; init; } = Array.Empty<string>();

    /// <summary>
    /// OS architecture (default arch for packages).
    /// </summary>
    [JsonPropertyName("osArch")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OsArch { get; init; }

    /// <summary>
    /// Include unofficial packages.
    /// </summary>
    [JsonPropertyName("includeUnofficial")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IncludeUnofficial { get; init; }

    /// <summary>
    /// Include candidate vulnerabilities.
    /// </summary>
    [JsonPropertyName("includeCandidates")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IncludeCandidates { get; init; }

    /// <summary>
    /// Include "any" version vulnerabilities.
    /// </summary>
    [JsonPropertyName("includeAnyVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool IncludeAnyVersion { get; init; }

    /// <summary>
    /// Add CVE list metrics to the response.
    /// </summary>
    [JsonPropertyName("cvelistMetrics")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    public bool CvelistMetrics { get; init; }
}

// ===================== Misc Service =====================

/// <summary>
/// Request payload for field suggestion.
/// </summary>
public record SuggestionRequest
{
    /// <summary>
    /// Field name to get suggestions for.
    /// </summary>
    [JsonPropertyName("fieldName")]
    public string FieldName { get; init; } = string.Empty;

    /// <summary>
    /// Suggestion type.
    /// </summary>
    [JsonPropertyName("type")]
    public string Type { get; init; } = "distinct";
}

/// <summary>
/// Response wrapper for suggestion endpoint.
/// </summary>
public record SuggestionResponseData
{
    /// <summary>
    /// Suggested values.
    /// </summary>
    [JsonPropertyName("suggest")]
    public IReadOnlyList<string> Suggest { get; init; } = Array.Empty<string>();
}

// ===================== Webhook =====================

/// <summary>
/// Response wrapper for webhook list.
/// </summary>
public record WebhookListResponseData
{
    /// <summary>
    /// Webhook subscriptions.
    /// </summary>
    [JsonPropertyName("subscriptions")]
    public IReadOnlyList<JsonElement> Subscriptions { get; init; } = Array.Empty<JsonElement>();
}

/// <summary>
/// Request payload for adding a webhook subscription.
/// </summary>
public record AddWebhookRequest
{
    /// <summary>
    /// API key.
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Lucene query for the webhook.
    /// </summary>
    [JsonPropertyName("query")]
    public string Query { get; init; } = string.Empty;
}

/// <summary>
/// Request payload for editing a webhook subscription.
/// </summary>
public record EditWebhookRequest
{
    /// <summary>
    /// API key.
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Subscription identifier.
    /// </summary>
    [JsonPropertyName("subscriptionid")]
    public string SubscriptionId { get; init; } = string.Empty;

    /// <summary>
    /// Active state as string: "true" or "false".
    /// </summary>
    [JsonPropertyName("active")]
    public string Active { get; init; } = "true";
}

/// <summary>
/// Request payload for removing a webhook subscription.
/// </summary>
public record RemoveWebhookRequest
{
    /// <summary>
    /// API key.
    /// </summary>
    [JsonPropertyName("apiKey")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ApiKey { get; init; }

    /// <summary>
    /// Subscription identifier.
    /// </summary>
    [JsonPropertyName("subscriptionid")]
    public string SubscriptionId { get; init; } = string.Empty;
}

// ===================== Subscription V4 =====================

/// <summary>
/// Request payload for creating a V4 subscription.
/// </summary>
public record SubscriptionV4CreateRequest
{
    /// <summary>
    /// Subscription name.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Query definition.
    /// </summary>
    [JsonPropertyName("query")]
    public Dictionary<string, object> Query { get; init; } = new();

    /// <summary>
    /// Delivery configuration.
    /// </summary>
    [JsonPropertyName("delivery")]
    public Dictionary<string, object> Delivery { get; init; } = new();

    /// <summary>
    /// Optional license identifier.
    /// </summary>
    [JsonPropertyName("licenseId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LicenseId { get; init; }

    /// <summary>
    /// Bulletin fields to include.
    /// </summary>
    [JsonPropertyName("bulletin_fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? BulletinFields { get; init; }

    /// <summary>
    /// Whether the subscription is active.
    /// </summary>
    [JsonPropertyName("is_active")]
    public bool IsActive { get; init; } = true;

    /// <summary>
    /// Timestamp source for filtering.
    /// </summary>
    [JsonPropertyName("timestamp_source")]
    public string TimestampSource { get; init; } = "modified";

    /// <summary>
    /// Whether to send notifications with empty results.
    /// </summary>
    [JsonPropertyName("send_empty_result")]
    public bool SendEmptyResult { get; init; }
}

/// <summary>
/// Request payload for updating a V4 subscription.
/// </summary>
public record SubscriptionV4UpdateRequest
{
    /// <summary>
    /// Subscription identifier.
    /// </summary>
    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    /// <summary>
    /// Subscription name.
    /// </summary>
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    /// <summary>
    /// Query definition.
    /// </summary>
    [JsonPropertyName("query")]
    public Dictionary<string, object> Query { get; init; } = new();

    /// <summary>
    /// Delivery configuration.
    /// </summary>
    [JsonPropertyName("delivery")]
    public Dictionary<string, object> Delivery { get; init; } = new();

    /// <summary>
    /// Optional license identifier.
    /// </summary>
    [JsonPropertyName("licenseId")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LicenseId { get; init; }

    /// <summary>
    /// Bulletin fields to include.
    /// </summary>
    [JsonPropertyName("bulletin_fields")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? BulletinFields { get; init; }

    /// <summary>
    /// Whether the subscription is active.
    /// </summary>
    [JsonPropertyName("is_active")]
    public bool IsActive { get; init; } = true;

    /// <summary>
    /// Timestamp source for filtering.
    /// </summary>
    [JsonPropertyName("timestamp_source")]
    public string TimestampSource { get; init; } = "modified";

    /// <summary>
    /// Whether to send notifications with empty results.
    /// </summary>
    [JsonPropertyName("send_empty_result")]
    public bool SendEmptyResult { get; init; }
}

// ===================== Report =====================

/// <summary>
/// Request payload for vulnerability reports.
/// </summary>
public record ReportRequest
{
    /// <summary>
    /// Report type discriminator.
    /// </summary>
    [JsonPropertyName("reporttype")]
    public string ReportType { get; init; } = string.Empty;

    /// <summary>
    /// Number of items to skip.
    /// </summary>
    [JsonPropertyName("skip")]
    public int Skip { get; init; }

    /// <summary>
    /// Maximum number of items to return.
    /// </summary>
    [JsonPropertyName("size")]
    public int Size { get; init; }

    /// <summary>
    /// Field filters.
    /// </summary>
    [JsonPropertyName("filter")]
    public Dictionary<string, object> Filter { get; init; } = new();

    /// <summary>
    /// Sort field (prefix with - for descending).
    /// </summary>
    [JsonPropertyName("sort")]
    public string Sort { get; init; } = string.Empty;
}

/// <summary>
/// Response wrapper for report endpoint.
/// </summary>
public record ReportResponseData
{
    /// <summary>
    /// Report entries.
    /// </summary>
    [JsonPropertyName("report")]
    public JsonElement Report { get; init; }
}
