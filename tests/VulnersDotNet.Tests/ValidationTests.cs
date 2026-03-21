using Microsoft.Extensions.DependencyInjection;
using VulnersDotNet.Extensions;
using VulnersDotNet.Models;

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
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Search.SearchAsync("")
        );
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SearchAsync_LimitTooLow_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => _client.Search.SearchAsync("test", limit: 0)
        );
        Assert.Equal("limit", ex.ParamName);
    }

    [Fact]
    public async Task SearchAsync_LimitTooHigh_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => _client.Search.SearchAsync("test", limit: 10001)
        );
        Assert.Equal("limit", ex.ParamName);
    }

    [Fact]
    public async Task GetBulletinAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Search.GetBulletinAsync("")
        );
        Assert.Equal("id", ex.ParamName);
    }

    [Fact]
    public async Task AutocompleteAsync_EmptyQuery_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Search.AutocompleteAsync("")
        );
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeAsync_EmptyProduct_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Search.SearchCpeAsync("")
        );
        Assert.Equal("product", ex.ParamName);
    }

    [Fact]
    public async Task SearchCpeAsync_SizeTooHigh_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => _client.Search.SearchCpeAsync("chrome", size: 10001)
        );
        Assert.Equal("size", ex.ParamName);
    }

    // ==================== Audit ====================

    [Fact]
    public async Task AuditPackagesAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Audit.AuditPackagesAsync("", "12", new[] { "pkg" })
        );
        Assert.Equal("os", ex.ParamName);
    }

    [Fact]
    public async Task AuditPackagesAsync_NullPackages_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _client.Audit.AuditPackagesAsync("debian", "12", null!)
        );
    }

    [Fact]
    public async Task AuditSoftwareAsync_NullSoftware_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _client.Audit.AuditSoftwareAsync(null!)
        );
    }

    [Fact]
    public async Task AuditHostAsync_NullSoftware_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => _client.Audit.AuditHostAsync(null!)
        );
    }

    [Fact]
    public async Task AuditWindowsKbAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Audit.AuditWindowsKbAsync("", new[] { "KB1234567" })
        );
        Assert.Equal("os", ex.ParamName);
    }

    // ==================== Archive ====================

    [Fact]
    public async Task DownloadDistributiveAsync_EmptyOs_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Archive.DownloadDistributiveAsync("", "12")
        );
        Assert.Equal("os", ex.ParamName);
    }

    [Fact]
    public async Task GetCollectionUpdateAsync_FutureTimestamp_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () =>
                _client.Archive.GetCollectionUpdateAsync(
                    "cve",
                    DateTimeOffset.UtcNow.AddHours(1)
                )
        );
        Assert.Equal("after", ex.ParamName);
    }

    [Fact]
    public async Task GetCollectionUpdateAsync_TooOld_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () =>
                _client.Archive.GetCollectionUpdateAsync(
                    "cve",
                    DateTimeOffset.UtcNow.AddHours(-26)
                )
        );
        Assert.Equal("after", ex.ParamName);
    }

    // ==================== Subscription ====================

    [Fact]
    public async Task SubscriptionAddAsync_EmptyQuery_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Subscription.AddAsync("", "test@example.com")
        );
        Assert.Equal("query", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionAddAsync_EmptyEmail_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Subscription.AddAsync("type:cve", "")
        );
        Assert.Equal("email", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionEditAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Subscription.EditAsync("")
        );
        Assert.Equal("subscriptionId", ex.ParamName);
    }

    [Fact]
    public async Task SubscriptionDeleteAsync_EmptyId_Throws()
    {
        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => _client.Subscription.DeleteAsync("")
        );
        Assert.Equal("subscriptionId", ex.ParamName);
    }

    // ==================== URL Configuration ====================

    [Fact]
    public void BaseUrl_TrailingSlashNormalized()
    {
        var options = new VulnersOptions { BaseUrl = "https://example.com/api/v3" };
        Assert.Equal("https://example.com/api/v3/", options.BaseUrl);
    }

    [Fact]
    public void V4BaseUrl_DerivedFromBaseUrl()
    {
        var options = new VulnersOptions { BaseUrl = "https://proxy.example.com/api/v3/" };
        Assert.Equal("https://proxy.example.com/api/v4/", options.V4BaseUrl);
    }

    [Fact]
    public void V4BaseUrl_ExplicitOverride()
    {
        var options = new VulnersOptions
        {
            BaseUrl = "https://example.com/api/v3/",
            V4BaseUrl = "https://other.example.com/v4",
        };
        Assert.Equal("https://other.example.com/v4/", options.V4BaseUrl);
    }

    [Fact]
    public void BaseUrl_EmptyThrows()
    {
        Assert.Throws<ArgumentException>(() => new VulnersOptions { BaseUrl = "" });
    }

    [Fact]
    public void BaseUrl_InvalidUrlThrows()
    {
        Assert.Throws<ArgumentException>(
            () => new VulnersOptions { BaseUrl = "not-a-url" }
        );
    }

    [Fact]
    public void Validate_NoV3Segment_WithoutExplicitV4_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
        {
            var services = new ServiceCollection();
            services.AddVulners(options =>
            {
                options.ApiKey = "key";
                options.BaseUrl = "https://proxy.example.com/vulners/";
                // V4BaseUrl not set — derivation is a no-op since there's no /v3/ segment
            });
        });
    }

    [Fact]
    public void Validate_NoV3Segment_WithExplicitV4_Succeeds()
    {
        var services = new ServiceCollection();
        services.AddVulners(options =>
        {
            options.ApiKey = "key";
            options.BaseUrl = "https://proxy.example.com/vulners/";
            options.V4BaseUrl = "https://proxy.example.com/vulners-v4/";
        });
        // Should not throw
    }
}
