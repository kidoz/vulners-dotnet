# VulnersDotNet

.NET SDK for the [Vulners.com](https://vulners.com) vulnerability intelligence API.

[![Language: C#](https://img.shields.io/badge/Language-C%23-blue.svg)](https://github.com/search?l=c%23)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- **Search** — Lucene full-text search, bulletin lookup by ID, query autocomplete, CPE search
- **Audit** — Linux package audit (RPM/DEB), Windows KB audit, Windows software audit, CPE-based software audit (V4), host context audit (V4)
- **Archive** — OS CVE archive download (ZIP), collection download and incremental updates
- **Subscription** — Email subscription management (list, add, edit, delete)
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
var cpes = await client.Search.SearchCpeAsync("google", "chrome", size: 5);
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

## API coverage

| Endpoint | Method |
|---|---|
| `POST /api/v3/search/lucene` | `Search.SearchAsync()` |
| `POST /api/v3/search/id` | `Search.GetBulletinAsync()` |
| `POST /api/v3/search/autocomplete` | `Search.AutocompleteAsync()` |
| `GET /api/v4/search/cpe` | `Search.SearchCpeAsync()` |
| `POST /api/v3/audit/audit` | `Audit.AuditPackagesAsync()` |
| `POST /api/v4/audit/software` | `Audit.AuditSoftwareAsync()` |
| `POST /api/v4/audit/host` | `Audit.AuditHostAsync()` |
| `POST /api/v3/audit/kb` | `Audit.AuditWindowsKbAsync()` |
| `POST /api/v3/audit/winaudit` | `Audit.AuditWindowsAsync()` |
| `GET /api/v3/audit/getSupportedOS` | `Audit.GetSupportedOsAsync()` |
| `GET /api/v3/archive/distributive` | `Archive.DownloadDistributiveAsync()` |
| `GET /api/v4/archive/collection` | `Archive.GetCollectionAsync()` |
| `GET /api/v4/archive/collection-update` | `Archive.GetCollectionUpdateAsync()` |
| `POST /api/v3/subscriptions/listEmailSubscriptions` | `Subscription.ListAsync()` |
| `POST /api/v3/subscriptions/addEmailSubscription` | `Subscription.AddAsync()` |
| `POST /api/v3/subscriptions/editEmailSubscription` | `Subscription.EditAsync()` |
| `POST /api/v3/subscriptions/removeEmailSubscription` | `Subscription.DeleteAsync()` |

## Configuration

```csharp
services.AddVulners(options =>
{
    options.ApiKey = "your-api-key";
    options.BaseUrl = "https://vulners.com/api/v3/";  // default
    options.Timeout = TimeSpan.FromSeconds(30);        // default
});
```

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
