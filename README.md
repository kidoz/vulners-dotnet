# VulnersDotNet

.NET SDK for the [Vulners.com](https://vulners.com) vulnerability intelligence API.

[![Language: C#](https://img.shields.io/badge/Language-C%23-blue.svg)](https://github.com/search?l=c%23)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- **Search** — Lucene full-text search (with auto-pagination), exploit search, bulletin lookup by ID, references, history, KB seeds/updates, query autocomplete, CPE search, web-path vulnerabilities
- **Audit** — Linux package audit (RPM/DEB/APK), Windows KB and software audit, CPE-based software and host audit (V4), CVE audit, library/SBOM/manifest/smart audit, package metadata (V4)
- **Archive** — OS CVE archive download (ZIP), collection and family download, incremental updates, and archive state
- **Subscriptions** — V4 subscriptions, legacy email subscriptions, and webhook subscriptions
- **Reports & STIX** — Linux Audit reports and STIX 2.1 bundle export
- **Secure by default** — API key sent only via the `X-Api-Key` header where possible, HTTPS enforced, and credentials redacted from error messages
- **Multi-target** — `net10.0`, `net8.0`, `netstandard2.0`
- **DI-friendly** — integrates with `Microsoft.Extensions.DependencyInjection`

## Installation

```bash
dotnet add package VulnersDotNet
```

## Quick start

```csharp
using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet;
using VulnersDotNet.Extensions;
using VulnersDotNet.Models;

var services = new ServiceCollection();
services.AddVulners(options =>
{
    options.ApiKey = Environment.GetEnvironmentVariable("VULNERS_API_KEY")!;
});

using var provider = services.BuildServiceProvider();
var client = provider.GetRequiredService<IVulnersClient>();
```

## Usage examples

### Search

```csharp
// Lucene search
var results = await client.Search.SearchAsync("type:cve", limit: 5);
foreach (var doc in results.Documents)
{
    Console.WriteLine($"[{doc.Source.Id}] {doc.Source.Title} (CVSS: {doc.Source.Cvss?.Score})");
}

// Get bulletin by ID
var bulletin = await client.Search.GetBulletinAsync("CVE-2021-44228");
Console.WriteLine($"{bulletin.Id}: {bulletin.Title}");

// Autocomplete
var suggestions = await client.Search.AutocompleteAsync("heartbleed");

// CPE search
var cpes = await client.Search.SearchCpeAsync("chrome", vendor: "google", size: 5);
Console.WriteLine($"Best match: {cpes.BestMatch}");
```

### Linux package audit

```csharp
var audit = await client.Audit.AuditPackagesAsync(
    os: "debian",
    version: "12",
    packages: new[] { "openssl 3.0.9-1 amd64" });

Console.WriteLine($"Vulnerabilities: {audit.Vulnerabilities.Count}");
Console.WriteLine($"Fix: {audit.CumulativeFix}");
```

### CPE-based software audit (V4)

```csharp
var results = await client.Audit.AuditSoftwareAsync(
    software: new CpeSoftwareInput[]
    {
        new CpeObject { Vendor = "openssl", Product = "openssl", Version = "3.0.9" }
    },
    match: "partial");

foreach (var item in results)
{
    Console.WriteLine($"CPE: {item.MatchedCriteria}");
    foreach (var vuln in item.Vulnerabilities)
    {
        Console.WriteLine($"  {vuln.Id}: {vuln.Title}");
    }
}
```

### Host context audit (V4)

```csharp
var results = await client.Audit.AuditHostAsync(
    software: new CpeSoftwareInput[]
    {
        new CpeObject { Part = "a", Vendor = "openssh", Product = "openssh", Version = "8.5" }
    },
    operatingSystem: new CpeObject
    {
        Part = "o", Vendor = "debian", Product = "debian_linux", Version = "12"
    });
```

### Windows KB audit

```csharp
var result = await client.Audit.AuditWindowsKbAsync(
    os: "Windows Server 2012 R2",
    kbList: new[] { "KB5009586", "KB5009624", "KB5008230" });

Console.WriteLine($"Missing KBs: {string.Join(", ", result.KbMissed)}");
```

### Windows software audit

```csharp
var result = await client.Audit.AuditWindowsAsync(
    os: "windows",
    osVersion: "10.0.19045",
    kbList: new[] { "KB5009586", "KB5009624" },
    software: new[]
    {
        new WindowsSoftwareEntry
        {
            Software = "7-Zip",
            Version = "19.00",
            TargetSw = "windows",
            TargetHw = "x64",
        },
    });

Console.WriteLine($"Vulnerabilities: {result.Vulnerabilities.Count}");
```

### Supported OS list

```csharp
var osList = await client.Audit.GetSupportedOsAsync();
Console.WriteLine(string.Join(", ", osList));
```

### Archive download

```csharp
using var zipStream = await client.Archive.DownloadDistributiveAsync("debian", "12");
using var fileStream = File.Create("debian-12-cves.zip");
await zipStream.CopyToAsync(fileStream);
```

### Email subscriptions

```csharp
// List subscriptions
var subs = await client.Subscription.ListAsync();

// Add a subscription
await client.Subscription.AddAsync(
    query: "type:cve AND cvss.score:[9 TO 10]",
    email: "alerts@example.com",
    format: "html");

// Edit a subscription
await client.Subscription.EditAsync(subscriptionId: "sub-id", active: "no");

// Delete a subscription
await client.Subscription.DeleteAsync(subscriptionId: "sub-id");
```

### V4 audit (CVE, library, SBOM)

```csharp
// Audit a single CVE
var cve = await client.Audit.AuditCveAsync("CVE-2021-44228");

// Audit library packages (purl or ecosystem strings)
var lib = await client.Audit.AuditLibraryAsync(new[] { "pkg:pypi/django@3.0.0" });

// Audit a package manifest (maven, pip, poetry, npm, golang, uv)
var pkg = await client.Audit.AuditPackageAsync("pip", "django==3.0.0\n");

// Audit an SBOM file (CycloneDX / SPDX)
using var sbom = File.OpenRead("sbom.json");
var sbomResult = await client.Audit.SbomAuditAsync(sbom, "sbom.json");
```

### API key info

```csharp
var info = await client.Misc.GetApiKeyInfoAsync();
Console.WriteLine($"{info.LicenseType} license, {info.Credit} credits (active: {info.Active})");
```

### Webhooks

```csharp
await client.Webhook.AddAsync("type:cve AND cvss.score:[9 TO 10]");
var hooks = await client.Webhook.ListAsync();
var pending = await client.Webhook.ReadAsync(subscriptionId: "hook-id", newestOnly: true);
await client.Webhook.EnableAsync(subscriptionId: "hook-id", active: false);
await client.Webhook.DeleteAsync(subscriptionId: "hook-id");
```

### Archive incremental sync

```csharp
// Current state (cursor + document count) of a collection
var state = await client.Archive.GetCollectionStateAsync("cve");
Console.WriteLine($"cursor: {state.Cursor}, docs: {state.TotalDocs}");

// Records changed in the last hour (max 25h window)
var updates = await client.Archive.GetCollectionUpdateAsync(
    "cve", DateTimeOffset.UtcNow.AddHours(-1));
```

### STIX bundle

```csharp
var bundle = await client.Stix.MakeBundleByIdAsync("CVE-2021-44228");
```

## API coverage

| Endpoint | Method |
|---|---|
| `POST /api/v3/search/lucene` | `Search.SearchAsync()` · `SearchAllAsync()` |
| `POST /api/v3/search/lucene` (exploits) | `Search.SearchExploitsAsync()` · `SearchExploitsAllAsync()` |
| `POST /api/v3/search/id` | `Search.GetBulletinAsync()` · `GetMultipleBulletinsAsync()` |
| `POST /api/v3/search/id` (references) | `Search.GetBulletinReferencesAsync()` · `GetMultipleBulletinReferencesAsync()` · `GetBulletinWithReferencesAsync()` · `GetMultipleBulletinsWithReferencesAsync()` |
| `GET /api/v3/search/history` | `Search.GetBulletinHistoryAsync()` |
| KB seeds / updates (via search) | `Search.GetKbSeedsAsync()` · `GetKbUpdatesAsync()` |
| `POST /api/v3/search/autocomplete` | `Search.AutocompleteAsync()` |
| `GET /api/v4/search/cpe` | `Search.SearchCpeAsync()` |
| `POST /api/v4/search/cpe` | `Search.SearchCpeMatchAsync()` |
| `POST /api/v4/search/web-vulns` | `Search.GetWebVulnsAsync()` |
| `POST /api/v3/search/suggest` | `Misc.GetSuggestionAsync()` |
| `GET /api/v3/apiKey/info` | `Misc.GetApiKeyInfoAsync()` |
| `POST /api/v3/audit/audit` | `Audit.AuditPackagesAsync()` |
| `POST /api/v4/audit/linux` | `Audit.LinuxAuditAsync()` |
| `POST /api/v4/audit/software` | `Audit.AuditSoftwareAsync()` |
| `POST /api/v4/audit/host` | `Audit.AuditHostAsync()` |
| `POST /api/v4/audit/cve` · `/cves` | `Audit.AuditCveAsync()` · `AuditCvesAsync()` |
| `POST /api/v4/audit/library` | `Audit.AuditLibraryAsync()` |
| `POST /api/v4/audit/smart` | `Audit.AuditSmartAsync()` |
| `POST /api/v4/audit/sbom` | `Audit.SbomAuditAsync()` |
| `POST /api/v4/audit/metadata` | `Audit.AuditPackageMetadataAsync()` |
| `POST /api/v4/audit/package/{type}` | `Audit.AuditPackageAsync()` |
| `POST /api/v3/audit/kb` | `Audit.AuditWindowsKbAsync()` |
| `POST /api/v3/audit/winaudit` | `Audit.AuditWindowsAsync()` |
| `GET /api/v3/audit/getSupportedOS` | `Audit.GetSupportedOsAsync()` |
| `GET /api/v3/archive/distributive` | `Archive.DownloadDistributiveAsync()` |
| `GET /api/v4/archive/collection` · `collection-update` · `collection-state` | `Archive.GetCollectionAsync()` · `GetCollectionUpdateAsync()` · `GetCollectionStateAsync()` |
| `GET /api/v4/archive/family` · `family-update` · `family-state` | `Archive.GetFamilyAsync()` · `GetFamilyUpdateAsync()` · `GetFamilyStateAsync()` |
| `GET/POST /api/v4/subscriptions/*` | `SubscriptionV4.GetListAsync()` · `GetAsync()` · `CreateAsync()` · `UpdateAsync()` · `DeleteAsync()` |
| `/api/v3/subscriptions/*EmailSubscription*` | `Subscription.ListAsync()` · `AddAsync()` · `EditAsync()` · `DeleteAsync()` |
| `/api/v3/subscriptions/*WebhookSubscription*` · `subscriptions/webhook` | `Webhook.ListAsync()` · `AddAsync()` · `EnableAsync()` · `ReadAsync()` · `DeleteAsync()` |
| `POST /api/v3/reports/vulnsreport` | `Report.GetVulnsSummaryAsync()` · `GetVulnsListAsync()` · `GetIpSummaryAsync()` · `GetScanListAsync()` · `GetHostVulnsAsync()` |
| `GET /api/v4/stix/bundle` | `Stix.MakeBundleByIdAsync()` |

## Configuration

```csharp
services.AddVulners(options =>
{
    options.ApiKey = "your-api-key";
    options.BaseUrl = "https://vulners.com/api/";  // default (version-agnostic root)
    // The "v3/" and "v4/" segments are appended automatically to form V3BaseUrl / V4BaseUrl.
    // Override them individually only for a proxy or non-standard layout:
    // options.V4BaseUrl = "https://proxy.example.com/api/v4/";
    options.Timeout = TimeSpan.FromSeconds(30);     // default
});
```

URLs must use HTTPS; plain `http://` is rejected except for loopback hosts (`localhost`, `127.0.0.1`, `::1`) to support local testing.

## Security

- The API key is attached to outbound requests via the `X-Api-Key` header on the configured `HttpClient`. A few legacy V3 endpoints (webhook create/read, Windows `winaudit`) additionally require the key in the query or body and are documented as exceptions in code.
- HTTPS is enforced for all non-loopback endpoints so the key is never sent over plaintext.
- HTTP error bodies are redacted (API keys, tokens) and truncated before being surfaced in `VulnersException` messages, so credentials do not leak into logs.
- The key is read from configuration/environment; never hardcode it. Keep `.env` out of version control.

## Project structure

```
vulners-dotnet/
├── src/
│   ├── VulnersDotNet/              # SDK library (net10.0;net8.0;netstandard2.0)
│   └── VulnersDotNet.Examples/     # Usage examples
└── tests/
    └── VulnersDotNet.Tests/        # Unit & integration tests (xUnit v3)
```

## Development

```bash
# Build
dotnet build

# Format code
dotnet csharpier format .

# Run tests (requires VULNERS_API_KEY env var)
VULNERS_API_KEY=your-key dotnet test
```

## License

[MIT](LICENSE) — Aleksandr Pavlov <ckidoz@gmail.com>
