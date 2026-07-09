using System.Text.Json;
using VulnersDotNet.Models;

namespace VulnersDotNet.Services;

/// <summary>
/// Defines the search capabilities of the Vulners API.
/// </summary>
public interface ISearchService
{
    /// <summary>
    /// Searches for vulnerabilities using Lucene syntax.
    /// </summary>
    /// <param name="query">The Lucene search query.</param>
    /// <param name="limit">The maximum number of results to return (max 10000).</param>
    /// <param name="skip">The number of results to skip.</param>
    /// <param name="fields">Optional list of fields to return in results.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SearchResponseData> SearchAsync(
        string query,
        int limit = 100,
        int skip = 0,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Searches for vulnerabilities and automatically pages through the result set
    /// until <paramref name="limit"/> documents (or all matches) have been collected.
    /// </summary>
    /// <param name="query">The Lucene search query.</param>
    /// <param name="limit">The maximum total number of results to collect (capped at 10000).</param>
    /// <param name="fields">Optional list of fields to return in results.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SearchResponseData> SearchAllAsync(
        string query,
        int limit = 100,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Retrieves a single bulletin by its ID with all fields.
    /// </summary>
    /// <param name="id">The bulletin ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<BulletinData> GetBulletinAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves multiple bulletins by their IDs.
    /// </summary>
    /// <param name="ids">The bulletin IDs.</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyDictionary<string, BulletinData>> GetMultipleBulletinsAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Retrieves references for a bulletin.
    /// </summary>
    /// <param name="id">The bulletin ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetBulletinReferencesAsync(
        string id,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Retrieves references for multiple bulletins, keyed by bulletin ID.
    /// </summary>
    /// <param name="ids">The bulletin IDs.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetMultipleBulletinReferencesAsync(
        IEnumerable<string> ids,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Retrieves a single bulletin together with its references
    /// (returns the raw <c>documents</c> + <c>references</c> payload).
    /// </summary>
    /// <param name="id">The bulletin ID.</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetBulletinWithReferencesAsync(
        string id,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Retrieves multiple bulletins together with their references
    /// (returns the raw <c>documents</c> + <c>references</c> payload).
    /// </summary>
    /// <param name="ids">The bulletin IDs.</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetMultipleBulletinsWithReferencesAsync(
        IEnumerable<string> ids,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns the change history of a bulletin.
    /// </summary>
    /// <param name="id">The bulletin ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetBulletinHistoryAsync(
        string id,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Searches for exploit bulletins.
    /// </summary>
    /// <param name="query">Software name or CVE ID.</param>
    /// <param name="lookupFields">Optional fields to restrict search to (e.g., "title").</param>
    /// <param name="limit">The maximum number of results.</param>
    /// <param name="skip">The number of results to skip.</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SearchResponseData> SearchExploitsAsync(
        string query,
        IEnumerable<string>? lookupFields = null,
        int limit = 20,
        int skip = 0,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Searches for exploit bulletins and automatically pages through the result set
    /// until <paramref name="limit"/> documents (or all matches) have been collected.
    /// </summary>
    /// <param name="query">Software name or CVE ID.</param>
    /// <param name="lookupFields">Optional fields to restrict search to (e.g., "title").</param>
    /// <param name="limit">The maximum total number of results to collect (capped at 10000).</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SearchResponseData> SearchExploitsAllAsync(
        string query,
        IEnumerable<string>? lookupFields = null,
        int limit = 100,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns superseeds and parentseeds for a Microsoft KB.
    /// </summary>
    /// <param name="kbId">Microsoft KB identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<KbSeedsResult> GetKbSeedsAsync(string kbId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns update bulletins for a Microsoft KB.
    /// </summary>
    /// <param name="kbId">Microsoft KB identifier.</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SearchResponseData> GetKbUpdatesAsync(
        string kbId,
        IEnumerable<string>? fields = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Searches for vulnerabilities related to web application paths.
    /// </summary>
    /// <param name="paths">URL paths to check.</param>
    /// <param name="application">Optional application filter.</param>
    /// <param name="match">Match mode: "partial" (default) or "full".</param>
    /// <param name="config">Optional configuration flags.</param>
    /// <param name="catalog">Catalog: "official" (default) or "extended".</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> GetWebVulnsAsync(
        IEnumerable<string> paths,
        object? application = null,
        string match = "partial",
        IEnumerable<string>? config = null,
        string catalog = "official",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns suggested completions for a partial Lucene query.
    /// </summary>
    /// <param name="query">The partial query string.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<string>> AutocompleteAsync(
        string query,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns CPE identifiers for a given product and optional vendor.
    /// </summary>
    /// <param name="product">Product name (e.g., "chrome").</param>
    /// <param name="vendor">Optional vendor name (e.g., "google").</param>
    /// <param name="size">Maximum number of CPEs to return (max 10000, 0 = all).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<CpeSearchResponseData> SearchCpeAsync(
        string product,
        string? vendor = null,
        int? size = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Resolves a batch of raw software strings to CPE match items (V4; 1..100 items).
    /// </summary>
    /// <param name="software">Raw software strings (each 1..512 chars).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> SearchCpeMatchAsync(
        IEnumerable<string> software,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Defines the audit capabilities of the Vulners API.
/// </summary>
public interface IAuditService
{
    /// <summary>
    /// Audits installed packages for a Linux host (RPM/DEB) — V3 API.
    /// </summary>
    /// <param name="os">The OS name (e.g., "debian", "centos").</param>
    /// <param name="version">The OS version.</param>
    /// <param name="packages">Installed packages.</param>
    /// <param name="includeCandidates">Whether to include advisories awaiting vendor status.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<AuditResponseData> AuditPackagesAsync(
        string os,
        string version,
        IEnumerable<string> packages,
        bool? includeCandidates = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits installed packages for a Linux host — V4 API with extended options.
    /// </summary>
    /// <param name="osName">OS name or ID (e.g., "ubuntu", "debian", "rhel").</param>
    /// <param name="osVersion">OS version.</param>
    /// <param name="packages">Installed packages (max 2500).</param>
    /// <param name="osArch">Optional OS architecture.</param>
    /// <param name="includeUnofficial">Include unofficial packages.</param>
    /// <param name="includeCandidates">Include candidate vulnerabilities.</param>
    /// <param name="includeAnyVersion">Include "any" version vulnerabilities.</param>
    /// <param name="cvelistMetrics">Add CVE list metrics to the response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> LinuxAuditAsync(
        string osName,
        string osVersion,
        IEnumerable<string> packages,
        string? osArch = null,
        bool includeUnofficial = false,
        bool includeCandidates = false,
        bool includeAnyVersion = false,
        bool cvelistMetrics = false,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits an SBOM file for vulnerabilities — V4 API.
    /// </summary>
    /// <param name="fileContent">Stream containing the SBOM file.</param>
    /// <param name="fileName">Name of the SBOM file.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> SbomAuditAsync(
        Stream fileContent,
        string fileName,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits software CPEs against the Vulners database (V4 API).
    /// </summary>
    /// <param name="software">List of CPE strings or <see cref="CpeObject"/> instances, wrapped as <see cref="CpeSoftwareInput"/>.</param>
    /// <param name="match">Matching strictness: "partial" (default) or "full".</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="config">Optional configuration flags.</param>
    /// <param name="catalog">Catalog: "official" (default) or "extended".</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<AuditSoftwareResult>> AuditSoftwareAsync(
        IEnumerable<CpeSoftwareInput> software,
        string? match = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? config = null,
        string? catalog = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits software in the context of a host OS/application/hardware (V4 API).
    /// </summary>
    /// <param name="software">Software CPEs installed on the host.</param>
    /// <param name="operatingSystem">Host OS (CPE string or <see cref="CpeObject"/>).</param>
    /// <param name="hardware">Optional hardware platform CPE.</param>
    /// <param name="application">Optional parent application CPE.</param>
    /// <param name="match">Matching strictness: "partial" (default) or "full".</param>
    /// <param name="fields">Optional list of fields to return.</param>
    /// <param name="config">Optional configuration flags.</param>
    /// <param name="catalog">Catalog: "official" (default) or "extended".</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<AuditSoftwareResult>> AuditHostAsync(
        IEnumerable<CpeSoftwareInput> software,
        CpeSoftwareInput? operatingSystem = null,
        CpeSoftwareInput? hardware = null,
        CpeSoftwareInput? application = null,
        string? match = null,
        IEnumerable<string>? fields = null,
        IEnumerable<string>? config = null,
        string? catalog = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits a Windows host by installed KB updates.
    /// </summary>
    Task<WindowsKbAuditResponseData> AuditWindowsKbAsync(
        string os,
        IEnumerable<string> kbList,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits a Windows host by installed KBs and software.
    /// </summary>
    Task<AuditResponseData> AuditWindowsAsync(
        string os,
        string osVersion,
        IEnumerable<string> kbList,
        IEnumerable<WindowsSoftwareEntry> software,
        string? platform = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns the list of operating systems supported by the audit endpoints.
    /// </summary>
    Task<IReadOnlyList<string>> GetSupportedOsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Audits a single CVE (or CAN) identifier for affected definitions (V4 apix).
    /// </summary>
    /// <param name="cve">CVE/CAN identifier, e.g. "CVE-2021-44228".</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditCveAsync(string cve, CancellationToken cancellationToken = default);

    /// <summary>
    /// Audits a batch of CVE (or CAN) identifiers (V4 apix; 1..500 items).
    /// </summary>
    /// <param name="cves">CVE/CAN identifiers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditCvesAsync(
        IEnumerable<string> cves,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits a list of library packages for vulnerabilities (V4 apix; 1..2500 packages).
    /// </summary>
    /// <param name="packages">Package identifiers.</param>
    /// <param name="includeUnofficial">Include unofficial packages.</param>
    /// <param name="includeCandidates">Include candidate vulnerabilities.</param>
    /// <param name="includeAnyVersion">Include "any" version vulnerabilities.</param>
    /// <param name="cvelistMetrics">Add CVE list metrics (non-free licenses only).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditLibraryAsync(
        IEnumerable<string> packages,
        bool includeUnofficial = false,
        bool includeCandidates = false,
        bool includeAnyVersion = false,
        bool cvelistMetrics = false,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Resolves and audits a list of free-form software strings (V4 apix; 1..500 items).
    /// </summary>
    /// <param name="software">Software strings (each 1..512 chars).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditSmartAsync(
        IEnumerable<string> software,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns metadata and known vulnerabilities for a specific package version (V4 apix).
    /// </summary>
    /// <param name="registry">Package registry / ecosystem (e.g., "pypi", "npm", "golang", "deb", "cargo").</param>
    /// <param name="name">Package name.</param>
    /// <param name="version">Package version.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditPackageMetadataAsync(
        string registry,
        string name,
        string version,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Audits a package-manager manifest/lockfile for vulnerabilities (V4 apix).
    /// </summary>
    /// <param name="contentType">Manifest ecosystem: "maven", "pip", "poetry", "npm", "golang", or "uv".</param>
    /// <param name="manifestContent">Raw manifest/lockfile content.</param>
    /// <param name="includeAnyVersion">Include "any" version vulnerabilities (default true).</param>
    /// <param name="includeCandidates">Include candidate vulnerabilities.</param>
    /// <param name="includeUnofficial">Include unofficial packages.</param>
    /// <param name="includeTransitives">Include transitive dependencies.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> AuditPackageAsync(
        string contentType,
        string manifestContent,
        bool includeAnyVersion = true,
        bool includeCandidates = false,
        bool includeUnofficial = false,
        bool includeTransitives = false,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Defines the archive/collection capabilities of the Vulners API.
/// </summary>
public interface IArchiveService
{
    /// <summary>
    /// Downloads a ZIP archive of CVEs for the specified OS and version.
    /// </summary>
    Task<Stream> DownloadDistributiveAsync(
        string os,
        string version,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Downloads a JSON collection by name (CDN-cached, updated every 4 hours).
    /// </summary>
    Task<IReadOnlyList<CollectionEntry>> GetCollectionAsync(
        string type,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets collection records updated after the given timestamp (max 25h in the past).
    /// </summary>
    Task<IReadOnlyList<CollectionEntry>> GetCollectionUpdateAsync(
        string type,
        DateTimeOffset after,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the current state (cursor, timestamps, document count) of a collection archive.
    /// </summary>
    /// <param name="type">Collection type (e.g., "cve").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ArchiveState> GetCollectionStateAsync(
        string type,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Downloads a full family archive by name (CDN-cached).
    /// </summary>
    /// <param name="name">Family name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<CollectionEntry>> GetFamilyAsync(
        string name,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets family records updated after the given timestamp (max 25h in the past).
    /// </summary>
    /// <param name="name">Family name.</param>
    /// <param name="after">Only return records newer than this timestamp.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<CollectionEntry>> GetFamilyUpdateAsync(
        string name,
        DateTimeOffset after,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets the current state (cursor, timestamps, document count) of a family archive.
    /// </summary>
    /// <param name="name">Family name.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ArchiveState> GetFamilyStateAsync(
        string name,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Defines the email subscription capabilities of the Vulners API (V3, deprecated).
/// </summary>
public interface ISubscriptionService
{
    /// <summary>
    /// Lists all email subscriptions for the authenticated user.
    /// </summary>
    Task<IReadOnlyList<EmailSubscription>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new email subscription.
    /// </summary>
    Task AddAsync(
        string query,
        string email,
        string? format = null,
        string? crontab = null,
        string? queryType = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Edits an existing email subscription.
    /// </summary>
    Task EditAsync(
        string subscriptionId,
        string? format = null,
        string? crontab = null,
        string? active = null,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Removes an email subscription.
    /// </summary>
    Task DeleteAsync(string subscriptionId, CancellationToken cancellationToken = default);
}

/// <summary>
/// Provides miscellaneous utility endpoints (field value suggestions).
/// </summary>
public interface IMiscService
{
    /// <summary>
    /// Returns distinct field value suggestions.
    /// </summary>
    /// <param name="fieldName">Field name to get suggestions for.</param>
    /// <param name="type">Suggestion type (default: "distinct").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IReadOnlyList<string>> GetSuggestionAsync(
        string fieldName,
        string type = "distinct",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Returns information about the configured API key and its license
    /// (name, active state, license type, expiration, and remaining credit).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ApiKeyInfo> GetApiKeyInfoAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Provides webhook subscription management.
/// </summary>
public interface IWebhookService
{
    /// <summary>
    /// Lists all webhook subscriptions.
    /// </summary>
    Task<IReadOnlyList<JsonElement>> ListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new webhook subscription.
    /// </summary>
    /// <param name="query">Lucene query for the webhook.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AddAsync(string query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enables or disables a webhook subscription.
    /// </summary>
    /// <param name="subscriptionId">Subscription identifier.</param>
    /// <param name="active">Whether the subscription should be active.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task EnableAsync(
        string subscriptionId,
        bool active,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Deletes a webhook subscription.
    /// </summary>
    /// <param name="subscriptionId">Subscription identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task DeleteAsync(string subscriptionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads pending webhook data.
    /// </summary>
    /// <param name="subscriptionId">Subscription identifier.</param>
    /// <param name="newestOnly">Whether to return only the newest data.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> ReadAsync(
        string subscriptionId,
        bool newestOnly = true,
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Provides V4 subscription management (replaces deprecated V3 email subscriptions).
/// </summary>
public interface ISubscriptionV4Service
{
    /// <summary>
    /// Lists all subscriptions.
    /// </summary>
    Task<JsonElement> GetListAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a subscription by ID.
    /// </summary>
    Task<JsonElement> GetAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new subscription.
    /// </summary>
    Task<JsonElement> CreateAsync(
        string name,
        Dictionary<string, object> query,
        Dictionary<string, object> delivery,
        string? licenseId = null,
        IEnumerable<string>? bulletinFields = null,
        bool isActive = true,
        string timestampSource = "modified",
        bool sendEmptyResult = false,
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Updates an existing subscription.
    /// </summary>
    Task<JsonElement> UpdateAsync(
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
    );

    /// <summary>
    /// Deletes a subscription.
    /// </summary>
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
}

/// <summary>
/// Provides Linux Audit vulnerability report capabilities.
/// </summary>
public interface IReportService
{
    /// <summary>
    /// Gets vulnerability summary report.
    /// </summary>
    Task<JsonElement> GetVulnsSummaryAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets vulnerability list report.
    /// </summary>
    Task<JsonElement> GetVulnsListAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets IP summary report.
    /// </summary>
    Task<JsonElement> GetIpSummaryAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets scan list report.
    /// </summary>
    Task<JsonElement> GetScanListAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    );

    /// <summary>
    /// Gets host vulnerabilities report.
    /// </summary>
    Task<JsonElement> GetHostVulnsAsync(
        int limit = 30,
        int offset = 0,
        Dictionary<string, object>? filter = null,
        string sort = "",
        CancellationToken cancellationToken = default
    );
}

/// <summary>
/// Provides STIX bundle generation.
/// </summary>
public interface IStixService
{
    /// <summary>
    /// Generates a STIX bundle for the given bulletin ID.
    /// </summary>
    /// <param name="id">Bulletin ID.</param>
    /// <param name="openctiId">Optional existing OpenCTI object ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<JsonElement> MakeBundleByIdAsync(
        string id,
        string? openctiId = null,
        CancellationToken cancellationToken = default
    );
}
