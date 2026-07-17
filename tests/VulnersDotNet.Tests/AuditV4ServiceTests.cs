using System.Text.Json;

namespace VulnersDotNet.Tests;

public class AuditV4ServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task AuditCveAsync_ReturnsAffectedPackages()
    {
        var result = await Client.Audit.AuditCveAsync(
            "CVE-2021-44228",
            TestContext.Current.CancellationToken
        );

        Assert.Equal(JsonValueKind.Object, result.ValueKind);
        Assert.True(result.TryGetProperty("cve", out _));
    }

    [Fact]
    public async Task AuditCvesAsync_ReturnsArray()
    {
        var result = await Client.Audit.AuditCvesAsync(
            new[] { "CVE-2021-44228", "CVE-2023-44487" },
            TestContext.Current.CancellationToken
        );

        Assert.Equal(JsonValueKind.Array, result.ValueKind);
        Assert.True(result.GetArrayLength() > 0);
    }

    [Fact]
    public async Task AuditSmartAsync_ResolvesSoftware()
    {
        const string software = "OpenSSL 1.0.1";
        var results = await Client.Audit.AuditSmartAsync(
            new[] { software },
            catalog: "official",
            cancellationToken: TestContext.Current.CancellationToken
        );

        var result = Assert.Single(results);
        Assert.Equal(software, result.Input);
        Assert.StartsWith("cpe:2.3:", result.Cpe, StringComparison.Ordinal);
        Assert.InRange(result.Confidence, 0, 1);
        Assert.NotEmpty(result.Vulnerabilities);

        var vulnerability = result.Vulnerabilities[0];
        Assert.False(string.IsNullOrEmpty(vulnerability.Id));
        Assert.NotEmpty(vulnerability.Reasons);
    }

    [Fact]
    public async Task AuditLibraryAsync_ReturnsIssues()
    {
        var result = await Client.Audit.AuditLibraryAsync(
            new[] { "pkg:pypi/django@3.0.0" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.Equal(JsonValueKind.Object, result.ValueKind);
        Assert.True(result.TryGetProperty("issues", out _));
        Assert.True(result.TryGetProperty("totalPackages", out _));
    }

    [Fact]
    public async Task AuditPackageMetadataAsync_ReturnsMetadata()
    {
        var result = await Client.Audit.AuditPackageMetadataAsync(
            registry: "pypi",
            name: "django",
            version: "3.0.0",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.Equal(JsonValueKind.Object, result.ValueKind);
    }

    [Fact]
    public async Task AuditPackageAsync_AuditsManifest()
    {
        var result = await Client.Audit.AuditPackageAsync(
            contentType: "pip",
            manifestContent: "django==3.0.0\n",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.Equal(JsonValueKind.Object, result.ValueKind);
        Assert.True(result.TryGetProperty("issues", out _));
    }
}
