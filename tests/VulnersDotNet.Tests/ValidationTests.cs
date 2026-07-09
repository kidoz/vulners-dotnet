using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet.Extensions;
using VulnersDotNet.Models;

// These tests exercise synchronous client-side argument validation and assert that
// the call throws before any async/network work, so a CancellationToken is irrelevant.
#pragma warning disable xUnit1051 // Calls to methods which accept CancellationToken should use TestContext.Current.CancellationToken

namespace VulnersDotNet.Tests;

/// <summary>
/// Unit tests for client-side input validation. These do NOT require an API key.
/// </summary>
public class ValidationTests
{
    private readonly IVulnersClient _client;

    public ValidationTests()
    {
        var services = new ServiceCollection();
        services.AddVulners(options =>
        {
            options.ApiKey = "test-key-for-validation";
        });
        var provider = services.BuildServiceProvider();
        _client = provider.GetRequiredService<IVulnersClient>();
    }

    // ==================== Search ====================

    [Fact]
    public async Task SearchAsync_EmptyQuery_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => _client.Search.SearchAsync(""));
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SearchAsync_LimitTooLow_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Search.SearchAsync("test", limit: 0)
        );
        Assert.Equal("limit", ex.ParamName);
    }

    [Fact]
    public async Task SearchAsync_LimitTooHigh_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Search.SearchAsync("test", limit: 10001)
        );
        Assert.Equal("limit", ex.ParamName);
    }

    [Fact]
    public async Task GetBulletinAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.GetBulletinAsync("")
        );
        Assert.Equal("id", ex.ParamName);
    }

    [Fact]
    public async Task AutocompleteAsync_EmptyQuery_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.AutocompleteAsync("")
        );
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeAsync_EmptyProduct_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.SearchCpeAsync("")
        );
        Assert.Equal("product", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeAsync_SizeTooHigh_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Search.SearchCpeAsync("chrome", size: 10001)
        );
        Assert.Equal("size", ex.ParamName);
    }

    // ==================== Audit ====================

    [Fact]
    public async Task AuditPackagesAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditPackagesAsync("", "12", new[] { "pkg" })
        );
        Assert.Equal("os", ex.ParamName);
    }

    [Fact]
    public async Task AuditPackagesAsync_NullPackages_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            _client.Audit.AuditPackagesAsync("debian", "12", null!)
        );
    }

    [Fact]
    public async Task AuditSoftwareAsync_NullSoftware_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            _client.Audit.AuditSoftwareAsync(null!)
        );
    }

    [Fact]
    public async Task AuditHostAsync_NullSoftware_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => _client.Audit.AuditHostAsync(null!));
    }

    [Fact]
    public async Task AuditWindowsKbAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditWindowsKbAsync("", new[] { "KB1234567" })
        );
        Assert.Equal("os", ex.ParamName);
    }

    // ==================== Collection bounds ====================

    [Fact]
    public async Task SearchAsync_NegativeSkip_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Search.SearchAsync("test", skip: -1)
        );
        Assert.Equal("skip", ex.ParamName);
    }

    [Fact]
    public async Task SearchAsync_SkipTooHigh_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Search.SearchAsync("test", skip: 10001)
        );
        Assert.Equal("skip", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeMatchAsync_Empty_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.SearchCpeMatchAsync(Array.Empty<string>())
        );
        Assert.Equal("software", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeMatchAsync_TooMany_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.SearchCpeMatchAsync(Enumerable.Repeat("nginx", 101))
        );
        Assert.Equal("software", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeMatchAsync_EmptyItem_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Search.SearchCpeMatchAsync(new[] { "nginx", "" })
        );
        Assert.Equal("software", ex.ParamName);
    }

    [Fact]
    public async Task AuditCvesAsync_Empty_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditCvesAsync(Array.Empty<string>())
        );
        Assert.Equal("cves", ex.ParamName);
    }

    [Fact]
    public async Task AuditCvesAsync_TooMany_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditCvesAsync(Enumerable.Repeat("CVE-2021-44228", 501))
        );
        Assert.Equal("cves", ex.ParamName);
    }

    [Fact]
    public async Task AuditLibraryAsync_Empty_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditLibraryAsync(Array.Empty<string>())
        );
        Assert.Equal("packages", ex.ParamName);
    }

    [Fact]
    public async Task LinuxAuditAsync_EmptyPackages_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.LinuxAuditAsync("debian", "12", Array.Empty<string>())
        );
        Assert.Equal("packages", ex.ParamName);
    }

    [Fact]
    public async Task AuditSoftwareAsync_Empty_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditSoftwareAsync(Array.Empty<CpeSoftwareInput>())
        );
        Assert.Equal("software", ex.ParamName);
    }

    [Fact]
    public async Task AuditHostAsync_TooMany_Throws()
    {
        var many = Enumerable.Repeat<CpeSoftwareInput>("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", 201);
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditHostAsync(many)
        );
        Assert.Equal("software", ex.ParamName);
    }

    [Fact]
    public async Task AuditPackagesAsync_EmptyPackages_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Audit.AuditPackagesAsync("debian", "12", Array.Empty<string>())
        );
        Assert.Equal("packages", ex.ParamName);
    }

    // ==================== Archive ====================

    [Fact]
    public async Task DownloadDistributiveAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Archive.DownloadDistributiveAsync("", "12")
        );
        Assert.Equal("os", ex.ParamName);
    }

    [Fact]
    public async Task GetCollectionUpdateAsync_FutureTimestamp_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Archive.GetCollectionUpdateAsync("cve", DateTimeOffset.UtcNow.AddHours(1))
        );
        Assert.Equal("after", ex.ParamName);
    }

    [Fact]
    public async Task GetCollectionUpdateAsync_TooOld_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            _client.Archive.GetCollectionUpdateAsync("cve", DateTimeOffset.UtcNow.AddHours(-26))
        );
        Assert.Equal("after", ex.ParamName);
    }

    // ==================== Subscription ====================

    [Fact]
    public async Task SubscriptionAddAsync_EmptyQuery_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Subscription.AddAsync("", "test@example.com")
        );
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionAddAsync_EmptyEmail_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Subscription.AddAsync("type:cve", "")
        );
        Assert.Equal("email", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionEditAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Subscription.EditAsync("")
        );
        Assert.Equal("subscriptionId", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionDeleteAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            _client.Subscription.DeleteAsync("")
        );
        Assert.Equal("subscriptionId", ex.ParamName);
    }

    // ==================== URL Configuration ====================

    [Fact]
    public void BaseUrl_TrailingSlashNormalized()
    {
        var options = new VulnersOptions { BaseUrl = "https://example.com/api" };
        Assert.Equal("https://example.com/api/", options.BaseUrl);
    }

    [Fact]
    public void DefaultBaseUrl_IsVersionAgnostic()
    {
        var options = new VulnersOptions();
        Assert.Equal("https://vulners.com/api/", options.BaseUrl);
        Assert.Equal("https://vulners.com/api/v3/", options.V3BaseUrl);
        Assert.Equal("https://vulners.com/api/v4/", options.V4BaseUrl);
    }

    [Fact]
    public void V3AndV4BaseUrl_DerivedFromBaseUrl()
    {
        var options = new VulnersOptions { BaseUrl = "https://proxy.example.com/api/" };
        Assert.Equal("https://proxy.example.com/api/v3/", options.V3BaseUrl);
        Assert.Equal("https://proxy.example.com/api/v4/", options.V4BaseUrl);
    }

    [Fact]
    public void V4BaseUrl_ExplicitOverride()
    {
        var options = new VulnersOptions
        {
            BaseUrl = "https://example.com/api/",
            V4BaseUrl = "https://other.example.com/v4",
        };
        Assert.Equal("https://other.example.com/v4/", options.V4BaseUrl);
        // V3 is still derived from BaseUrl and unaffected by the V4 override.
        Assert.Equal("https://example.com/api/v3/", options.V3BaseUrl);
    }

    [Fact]
    public void V3BaseUrl_ExplicitOverride()
    {
        var options = new VulnersOptions
        {
            BaseUrl = "https://example.com/api/",
            V3BaseUrl = "https://legacy.example.com/v3",
        };
        Assert.Equal("https://legacy.example.com/v3/", options.V3BaseUrl);
        Assert.Equal("https://example.com/api/v4/", options.V4BaseUrl);
    }

    [Fact]
    public void BaseUrl_EmptyThrows()
    {
        Assert.Throws<ArgumentException>(() => new VulnersOptions { BaseUrl = "" });
    }

    [Fact]
    public void BaseUrl_InvalidUrlThrows()
    {
        Assert.Throws<ArgumentException>(() => new VulnersOptions { BaseUrl = "not-a-url" });
    }

    [Fact]
    public void BaseUrl_PlainHttpNonLoopback_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new VulnersOptions { BaseUrl = "http://vulners.com/api/" }
        );
        Assert.Contains("HTTPS", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BaseUrl_HttpsAllowed()
    {
        var options = new VulnersOptions { BaseUrl = "https://example.com/api/" };
        Assert.Equal("https://example.com/api/", options.BaseUrl);
    }

    [Theory]
    [InlineData("http://localhost:8080/api/")]
    [InlineData("http://127.0.0.1/api/")]
    public void BaseUrl_PlainHttpLoopback_Allowed(string url)
    {
        var options = new VulnersOptions { BaseUrl = url };
        Assert.StartsWith("http://", options.BaseUrl);
    }

    [Fact]
    public void V4BaseUrl_PlainHttpNonLoopback_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new VulnersOptions { V4BaseUrl = "http://proxy.example.com/api/v4/" }
        );
    }

    [Fact]
    public void Validate_CustomProxyBase_Succeeds()
    {
        var services = new ServiceCollection();
        services.AddVulners(options =>
        {
            options.ApiKey = "key";
            options.BaseUrl = "https://proxy.example.com/vulners/";
        });
        // Should not throw — v3/ and v4/ are derived from the version-agnostic base.
    }
}
