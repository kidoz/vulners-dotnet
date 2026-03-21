using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet;
using VulnersDotNet.Extensions;
using VulnersDotNet.Models;

// Read API key from environment variable
var apiKey =
    Environment.GetEnvironmentVariable("VULNERS_API_KEY")
    ?? throw new InvalidOperationException("Set the VULNERS_API_KEY environment variable.");

// Configure services
var services = new ServiceCollection();
services.AddVulners(options =>
{
    options.ApiKey = apiKey;
});

using var provider = services.BuildServiceProvider();
var client = provider.GetRequiredService<IVulnersClient>();

// --- Lucene Search ---
Console.WriteLine("=== Lucene Search ===");
var searchResult = await client.Search.SearchAsync("type:cve", limit: 5);
Console.WriteLine($"Total results: {searchResult.Total}");
foreach (var doc in searchResult.Documents)
{
    Console.WriteLine($"  [{doc.Source.Id}] {doc.Source.Title} (CVSS: {doc.Source.Cvss?.Score})");
}

// --- Get bulletin by ID ---
Console.WriteLine("\n=== Get Bulletin by ID ===");
var bulletin = await client.Search.GetBulletinAsync("CVE-2024-0001");
Console.WriteLine($"  ID:          {bulletin.Id}");
Console.WriteLine($"  Title:       {bulletin.Title}");
Console.WriteLine($"  Type:        {bulletin.Type}");
Console.WriteLine($"  Published:   {bulletin.Published}");
Console.WriteLine($"  CVSS:        {bulletin.Cvss?.Score} ({bulletin.Cvss?.Severity})");

// --- Autocomplete ---
Console.WriteLine("\n=== Autocomplete ===");
var suggestions = await client.Search.AutocompleteAsync("heartbleed");
Console.WriteLine($"  Suggestions: {string.Join(", ", suggestions.Take(5))}");

// --- CPE Search ---
Console.WriteLine("\n=== CPE Search ===");
var cpeResult = await client.Search.SearchCpeAsync("chrome", vendor: "google", size: 3);
Console.WriteLine($"  Best match: {cpeResult.BestMatch}");
foreach (var cpe in cpeResult.Cpe)
{
    Console.WriteLine($"    {cpe}");
}

// --- Linux Package Audit ---
Console.WriteLine("\n=== Linux Package Audit ===");
var auditResult = await client.Audit.AuditPackagesAsync(
    os: "debian",
    version: "12",
    packages: new[] { "openssl 3.0.9-1 amd64" }
);
Console.WriteLine($"  Vulnerabilities: {auditResult.Vulnerabilities.Count}");
Console.WriteLine($"  CVEs: {string.Join(", ", auditResult.CveList.Take(5))}");
if (auditResult.CumulativeFix is not null)
    Console.WriteLine($"  Fix: {auditResult.CumulativeFix}");

// --- V4 Software Audit (CPE) ---
Console.WriteLine("\n=== V4 Software Audit ===");
var softwareResults = await client.Audit.AuditSoftwareAsync(
    software: new CpeSoftwareInput[]
    {
        new CpeObject
        {
            Vendor = "openssl",
            Product = "openssl",
            Version = "3.0.9",
        },
    },
    match: "partial"
);
foreach (var item in softwareResults)
{
    Console.WriteLine($"  CPE: {item.MatchedCriteria}");
    Console.WriteLine($"  Vulnerabilities: {item.Vulnerabilities.Count}");
    foreach (var vuln in item.Vulnerabilities.Take(3))
    {
        Console.WriteLine($"    {vuln.Id}: {vuln.Title}");
    }
}

// --- Supported OS ---
Console.WriteLine("\n=== Supported OS ===");
var osList = await client.Audit.GetSupportedOsAsync();
Console.WriteLine($"  {string.Join(", ", osList.Take(10))}...");

// --- Archive Download ---
Console.WriteLine("\n=== Archive Download ===");
using var zipStream = await client.Archive.DownloadDistributiveAsync("debian", "12");
Console.WriteLine($"  ZIP stream received, readable: {zipStream.CanRead}");
