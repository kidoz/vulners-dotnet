using VulnersDotNet.Models;

namespace VulnersDotNet.Tests;

public class AuditServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task AuditPackagesAsync_ReturnsVulnerabilities()
    {
        var result = await Client.Audit.AuditPackagesAsync(
            os: "debian",
            version: "12",
            packages: new[] { "openssl 3.0.9-1 amd64" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.NotEmpty(result.Vulnerabilities);
        Assert.NotEmpty(result.CveList);
        Assert.NotNull(result.CumulativeFix);
        Assert.NotNull(result.Cvss);
    }

    [Fact]
    public async Task AuditPackagesAsync_PackagesContainAdvisories()
    {
        var result = await Client.Audit.AuditPackagesAsync(
            os: "debian",
            version: "12",
            packages: new[] { "openssl 3.0.9-1 amd64" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEmpty(result.Packages);

        foreach (var (packageKey, bulletins) in result.Packages)
        {
            Assert.False(string.IsNullOrEmpty(packageKey));
            foreach (var (bulletinId, advisories) in bulletins)
            {
                Assert.False(string.IsNullOrEmpty(bulletinId));
                Assert.NotEmpty(advisories);

                var advisory = advisories[0];
                Assert.False(string.IsNullOrEmpty(advisory.BulletinId));
                Assert.False(string.IsNullOrEmpty(advisory.ProvidedVersion));
                Assert.NotNull(advisory.Fix);
            }
        }
    }

    [Fact]
    public async Task AuditSoftwareAsync_WithCpeStrings_ReturnsResults()
    {
        var results = await Client.Audit.AuditSoftwareAsync(
            software: new CpeSoftwareInput[] { "cpe:2.3:a:openssl:openssl:3.0.9:*:*:*:*:*:*:*" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(results);
        Assert.NotEmpty(results);
        Assert.NotEmpty(results[0].Vulnerabilities);
    }

    [Fact]
    public async Task AuditSoftwareAsync_WithCpeObjects_ReturnsResults()
    {
        var results = await Client.Audit.AuditSoftwareAsync(
            software: new CpeSoftwareInput[]
            {
                new CpeObject
                {
                    Vendor = "openssl",
                    Product = "openssl",
                    Version = "3.0.9",
                },
            },
            match: "partial",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(results);
        Assert.NotEmpty(results);
        Assert.NotEmpty(results[0].Vulnerabilities);
    }

    [Fact]
    public async Task AuditHostAsync_ReturnsResults()
    {
        var results = await Client.Audit.AuditHostAsync(
            software: new CpeSoftwareInput[]
            {
                new CpeObject
                {
                    Part = "a",
                    Vendor = "apache",
                    Product = "http_server",
                    Version = "2.4.49",
                },
            },
            operatingSystem: new CpeObject
            {
                Part = "o",
                Vendor = "debian",
                Product = "debian_linux",
                Version = "11",
            },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(results);
        Assert.NotEmpty(results);
    }

    [Fact]
    public async Task AuditWindowsKbAsync_ReturnsResults()
    {
        var result = await Client.Audit.AuditWindowsKbAsync(
            os: "Windows Server 2012 R2",
            kbList: new[] { "KB5009586", "KB5009624", "KB5008230" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.NotEmpty(result.KbMissed);
        Assert.NotEmpty(result.CveList);
    }

    [Fact]
    public async Task AuditWindowsAsync_ReturnsResults()
    {
        var result = await Client.Audit.AuditWindowsAsync(
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
            },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.NotEmpty(result.Vulnerabilities);
        Assert.NotEmpty(result.CveList);
    }

    [Fact]
    public async Task LinuxAuditAsync_ReturnsResults()
    {
        var result = await Client.Audit.LinuxAuditAsync(
            osName: "debian",
            osVersion: "12",
            packages: new[] { "openssl 3.0.9-1 amd64" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEqual(default, result);
    }

    [Fact]
    public async Task GetSupportedOsAsync_ReturnsList()
    {
        var osList = await Client.Audit.GetSupportedOsAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(osList);
        Assert.NotEmpty(osList);
        Assert.Contains(
            osList,
            os => os.Contains("debian", System.StringComparison.OrdinalIgnoreCase)
        );
    }

    [Fact]
    public async Task SbomAuditAsync_ReturnsResults()
    {
        const string sbom =
            /*lang=json,strict*/
            "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.4\",\"version\":1,"
            + "\"components\":[{\"type\":\"library\",\"name\":\"log4j-core\",\"version\":\"2.14.1\","
            + "\"purl\":\"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1\"}]}";

        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(sbom));
        var result = await Client.Audit.SbomAuditAsync(
            stream,
            "sbom.json",
            TestContext.Current.CancellationToken
        );

        Assert.Equal(System.Text.Json.JsonValueKind.Object, result.ValueKind);
        Assert.True(result.TryGetProperty("data", out _));
    }
}
