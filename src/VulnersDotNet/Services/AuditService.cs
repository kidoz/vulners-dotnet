using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Implementation of the audit service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by DI"
)]
internal sealed class AuditService : BaseApiService, IAuditService
{
    public AuditService(HttpClient httpClient, VulnersOptions options)
        : base(httpClient, options) { }

    /// <inheritdoc />
    public Task<AuditResponseData> AuditPackagesAsync(
        string os,
        string version,
        IEnumerable<string> packages,
        bool? includeCandidates = null,
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
        var packageList = ValidateCount(packages, nameof(packages), 1, int.MaxValue);

        var request = new AuditRequest
        {
            OS = os,
            Version = version,
            Packages = packageList,
            IncludeCandidates = includeCandidates,
        };

        return PostAsync<AuditRequest, AuditResponseData>(
            "audit/audit/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditSoftwareResult>> AuditSoftwareAsync(
        IEnumerable<CpeSoftwareInput> software,
        string? match = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? config = null,
        string? catalog = null,
        CancellationToken cancellationToken = default
    )
    {
        var items = ValidateCount(software, nameof(software), 1, 500);
        var request = new AuditSoftwareRequest
        {
            Software = items.Select(s => s.Value),
            Match = match,
            Fields = fields,
            Config = config,
            Catalog = catalog,
        };

        return await PostV4Async<AuditSoftwareRequest, List<AuditSoftwareResult>>(
                "audit/software",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditSoftwareResult>> AuditHostAsync(
        IEnumerable<CpeSoftwareInput> software,
        CpeSoftwareInput? operatingSystem = null,
        CpeSoftwareInput? hardware = null,
        CpeSoftwareInput? application = null,
        string? match = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? config = null,
        string? catalog = null,
        CancellationToken cancellationToken = default
    )
    {
        var items = ValidateCount(software, nameof(software), 1, 200);
        var request = new AuditHostRequest
        {
            Software = items.Select(s => s.Value),
            OperatingSystem = operatingSystem?.Value,
            Hardware = hardware?.Value,
            Application = application?.Value,
            Match = match,
            Fields = fields,
            Config = config,
            Catalog = catalog,
        };

        return await PostV4Async<AuditHostRequest, List<AuditSoftwareResult>>(
                "audit/host",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<JsonElement> LinuxAuditAsync(
        string osName,
        string osVersion,
        IEnumerable<string> packages,
        string? osArch = null,
        bool includeUnofficial = false,
        bool includeCandidates = false,
        bool includeAnyVersion = false,
        bool cvelistMetrics = false,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(osName);
        ArgumentException.ThrowIfNullOrEmpty(osVersion);
#else
        if (string.IsNullOrEmpty(osName))
            throw new ArgumentException("Value cannot be null or empty.", nameof(osName));
        if (string.IsNullOrEmpty(osVersion))
            throw new ArgumentException("Value cannot be null or empty.", nameof(osVersion));
#endif
        var packageList = ValidateStringItems(packages, nameof(packages), 1, 2500);

        var request = new LinuxAuditRequest
        {
            OsName = osName,
            OsVersion = osVersion,
            Packages = packageList,
            OsArch = osArch,
            IncludeUnofficial = includeUnofficial,
            IncludeCandidates = includeCandidates,
            IncludeAnyVersion = includeAnyVersion,
            CvelistMetrics = cvelistMetrics,
        };

        return PostV4Async<LinuxAuditRequest, JsonElement>(
            "audit/linux",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public async Task<JsonElement> SbomAuditAsync(
        Stream fileContent,
        string fileName,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentNullException.ThrowIfNull(fileContent);
        ArgumentException.ThrowIfNullOrEmpty(fileName);
#else
        if (fileContent == null)
            throw new ArgumentNullException(nameof(fileContent));
        if (string.IsNullOrEmpty(fileName))
            throw new ArgumentException("Value cannot be null or empty.", nameof(fileName));
#endif

        using var streamContent = new StreamContent(fileContent);
        using var content = new MultipartFormDataContent();
        content.Add(streamContent, "file", fileName);
        return await PostV4MultipartAsync<JsonElement>("audit/sbom", content, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<WindowsKbAuditResponseData> AuditWindowsKbAsync(
        string os,
        IEnumerable<string> kbList,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(os);
        ArgumentNullException.ThrowIfNull(kbList);
#else
        if (string.IsNullOrEmpty(os))
            throw new ArgumentException("Value cannot be null or empty.", nameof(os));
        if (kbList == null)
            throw new ArgumentNullException(nameof(kbList));
#endif

        var request = new WindowsKbAuditRequest { OS = os, KbList = kbList };

        return PostAsync<WindowsKbAuditRequest, WindowsKbAuditResponseData>(
            "audit/kb/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public Task<AuditResponseData> AuditWindowsAsync(
        string os,
        string osVersion,
        IEnumerable<string> kbList,
        IEnumerable<WindowsSoftwareEntry> software,
        string? platform = null,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(os);
        ArgumentException.ThrowIfNullOrEmpty(osVersion);
        ArgumentNullException.ThrowIfNull(kbList);
        ArgumentNullException.ThrowIfNull(software);
#else
        if (string.IsNullOrEmpty(os))
            throw new ArgumentException("Value cannot be null or empty.", nameof(os));
        if (string.IsNullOrEmpty(osVersion))
            throw new ArgumentException("Value cannot be null or empty.", nameof(osVersion));
        if (kbList == null)
            throw new ArgumentNullException(nameof(kbList));
        if (software == null)
            throw new ArgumentNullException(nameof(software));
#endif

        // LEGACY EXCEPTION: the winaudit endpoint reads apiKey from the request body and
        // fails without it, so the key is sent here in addition to the X-Api-Key header.
        var request = new WindowsWinAuditRequest
        {
            ApiKey = ApiKey,
            OS = os,
            OsVersion = osVersion,
            KbList = kbList,
            Software = software,
            Platform = platform,
        };

        return PostAsync<WindowsWinAuditRequest, AuditResponseData>(
            "audit/winaudit/",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetSupportedOsAsync(
        CancellationToken cancellationToken = default
    )
    {
        var response = await GetAsync<SupportedOsResponseData>(
                "audit/getSupportedOS",
                cancellationToken
            )
            .ConfigureAwait(false);
        return new List<string>(response.SupportedOs.Keys);
    }

    /// <inheritdoc />
    public Task<JsonElement> AuditCveAsync(
        string cve,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(cve);
#else
        if (string.IsNullOrEmpty(cve))
            throw new ArgumentException("Value cannot be null or empty.", nameof(cve));
#endif

        var request = new CveAuditRequest { Cve = cve };
        return PostV4Async<CveAuditRequest, JsonElement>("audit/cve", request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> AuditCvesAsync(
        IEnumerable<string> cves,
        CancellationToken cancellationToken = default
    )
    {
        var items = ValidateStringItems(cves, nameof(cves), 1, 500);
        var request = new CvesAuditRequest { Cve = items };
        return PostV4Async<CvesAuditRequest, JsonElement>("audit/cves", request, cancellationToken);
    }

    /// <inheritdoc />
    public Task<JsonElement> AuditLibraryAsync(
        IEnumerable<string> packages,
        bool includeUnofficial = false,
        bool includeCandidates = false,
        bool includeAnyVersion = false,
        bool cvelistMetrics = false,
        CancellationToken cancellationToken = default
    )
    {
        var packageList = ValidateStringItems(packages, nameof(packages), 1, 2500);
        var request = new LibraryAuditRequest
        {
            Packages = packageList,
            IncludeUnofficial = includeUnofficial,
            IncludeCandidates = includeCandidates,
            IncludeAnyVersion = includeAnyVersion,
            CvelistMetrics = cvelistMetrics,
        };

        return PostV4Async<LibraryAuditRequest, JsonElement>(
            "audit/library",
            request,
            cancellationToken
        );
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SmartAuditResult>> AuditSmartAsync(
        IEnumerable<string> software,
        CancellationToken cancellationToken = default
    ) => AuditSmartAsync(software, "official", cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<SmartAuditResult>> AuditSmartAsync(
        IEnumerable<string> software,
        string catalog,
        CancellationToken cancellationToken = default
    )
    {
        var items = ValidateStringItems(software, nameof(software), 1, 500, maxItemLength: 512);
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(catalog);
#else
        if (string.IsNullOrEmpty(catalog))
            throw new ArgumentException("Value cannot be null or empty.", nameof(catalog));
#endif
        if (
            !string.Equals(catalog, "official", StringComparison.Ordinal)
            && !string.Equals(catalog, "extended", StringComparison.Ordinal)
        )
        {
            throw new ArgumentException(
                "Catalog must be either 'official' or 'extended'.",
                nameof(catalog)
            );
        }

        var request = new SmartAuditRequest { Software = items, Catalog = catalog };
        return await PostV4Async<SmartAuditRequest, List<SmartAuditResult>>(
                "audit/smart",
                request,
                cancellationToken
            )
            .ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task<JsonElement> AuditPackageMetadataAsync(
        string registry,
        string name,
        string version,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(registry);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(version);
#else
        if (string.IsNullOrEmpty(registry))
            throw new ArgumentException("Value cannot be null or empty.", nameof(registry));
        if (string.IsNullOrEmpty(name))
            throw new ArgumentException("Value cannot be null or empty.", nameof(name));
        if (string.IsNullOrEmpty(version))
            throw new ArgumentException("Value cannot be null or empty.", nameof(version));
#endif

        var request = new PackageMetadataRequest
        {
            Registry = registry,
            Name = name,
            Version = version,
        };

        return PostV4Async<PackageMetadataRequest, JsonElement>(
            "audit/metadata",
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
    public Task<JsonElement> AuditPackageAsync(
        string contentType,
        string manifestContent,
        bool includeAnyVersion = true,
        bool includeCandidates = false,
        bool includeUnofficial = false,
        bool includeTransitives = false,
        CancellationToken cancellationToken = default
    )
    {
#if NET8_0_OR_GREATER
        ArgumentException.ThrowIfNullOrEmpty(contentType);
        ArgumentNullException.ThrowIfNull(manifestContent);
#else
        if (string.IsNullOrEmpty(contentType))
            throw new ArgumentException("Value cannot be null or empty.", nameof(contentType));
        if (manifestContent == null)
            throw new ArgumentNullException(nameof(manifestContent));
#endif

        var url =
            $"audit/package/{Uri.EscapeDataString(contentType)}"
            + $"?includeAnyVersion={(includeAnyVersion ? "true" : "false")}"
            + $"&includeCandidates={(includeCandidates ? "true" : "false")}"
            + $"&includeUnofficial={(includeUnofficial ? "true" : "false")}"
            + $"&includeTransitives={(includeTransitives ? "true" : "false")}";

        return PostV4RawAsync<JsonElement>(url, manifestContent, "text/plain", cancellationToken);
    }
}
