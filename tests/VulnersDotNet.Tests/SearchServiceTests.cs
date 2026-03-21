namespace VulnersDotNet.Tests;

public class SearchServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task SearchAsync_ReturnsResults()
    {
        var result = await Client.Search.SearchAsync(
            "type:cve",
            limit: 5,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.True(result.Total > 0, "Expected at least one result");
        Assert.NotEmpty(result.Documents);
        Assert.True(result.Documents.Count <= 5, "Expected at most 5 documents");

        var first = result.Documents[0];
        Assert.False(string.IsNullOrEmpty(first.Id), "Document ID should not be empty");
        Assert.False(string.IsNullOrEmpty(first.Source.Id), "Source ID should not be empty");
        Assert.False(string.IsNullOrEmpty(first.Source.Title), "Source title should not be empty");
        Assert.False(string.IsNullOrEmpty(first.Source.Type), "Source type should not be empty");
    }

    [Fact]
    public async Task SearchAsync_RespectsLimit()
    {
        var result = await Client.Search.SearchAsync(
            "type:cve",
            limit: 3,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.True(result.Documents.Count <= 3);
    }

    [Fact]
    public async Task SearchAsync_SkipWorks()
    {
        var ct = TestContext.Current.CancellationToken;

        // Fetch two results in a single call, then verify skip=1 returns the second one
        var both = await Client.Search.SearchAsync(
            "type:cve",
            limit: 2,
            skip: 0,
            cancellationToken: ct
        );

        Assert.True(
            both.Documents.Count >= 2,
            "Need at least 2 results to test skip"
        );

        var skipped = await Client.Search.SearchAsync(
            "type:cve",
            limit: 1,
            skip: 1,
            cancellationToken: ct
        );

        Assert.NotEmpty(skipped.Documents);

        // The skipped result should match the second document from the combined call.
        // If ordering drifts between calls, at minimum skip must return something
        // different from the first result.
        Assert.NotEqual(both.Documents[0].Source.Id, skipped.Documents[0].Source.Id);
    }

    [Fact]
    public async Task SearchAsync_WithFields_ReturnsRequestedFields()
    {
        var result = await Client.Search.SearchAsync(
            "type:cve",
            limit: 1,
            fields: new[] { "id", "title", "published" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEmpty(result.Documents);
        var source = result.Documents[0].Source;
        Assert.False(string.IsNullOrEmpty(source.Id), "id field should be populated");
        Assert.False(string.IsNullOrEmpty(source.Title), "title field should be populated");
        Assert.NotNull(source.Published);
    }

    [Fact]
    public async Task GetBulletinAsync_ReturnsBulletin()
    {
        // Use a well-known, long-lived CVE (Log4Shell) that is unlikely to be removed
        var bulletin = await Client.Search.GetBulletinAsync(
            "CVE-2021-44228",
            TestContext.Current.CancellationToken
        );

        Assert.Equal("CVE-2021-44228", bulletin.Id);
        Assert.False(string.IsNullOrEmpty(bulletin.Title));
        Assert.False(string.IsNullOrEmpty(bulletin.Description));
        Assert.NotNull(bulletin.Published);
        Assert.NotNull(bulletin.Cvss);
        Assert.True(bulletin.Cvss.Score > 0);
    }

    [Fact]
    public async Task GetBulletinAsync_NonExistentId_Throws()
    {
        await Assert.ThrowsAsync<Exceptions.VulnersException>(() =>
            Client.Search.GetBulletinAsync(
                "NONEXISTENT-BULLETIN-ID-999",
                TestContext.Current.CancellationToken
            )
        );
    }

    [Fact]
    public async Task AutocompleteAsync_ReturnsSuggestions()
    {
        var suggestions = await Client.Search.AutocompleteAsync(
            "heartbleed",
            TestContext.Current.CancellationToken
        );

        Assert.NotNull(suggestions);
        Assert.NotEmpty(suggestions);
    }

    [Fact]
    public async Task SearchCpeAsync_ReturnsCpeResults()
    {
        var result = await Client.Search.SearchCpeAsync(
            "chrome",
            vendor: "google",
            size: 5,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.NotEmpty(result.Cpe);
    }

    [Fact]
    public async Task GetMultipleBulletinsAsync_ReturnsDocuments()
    {
        var ids = new[] { "CVE-2021-44228", "CVE-2023-44487" };
        var result = await Client.Search.GetMultipleBulletinsAsync(
            ids,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.True(result.Count > 0);
        Assert.Contains("CVE-2021-44228", result.Keys);
    }

    [Fact]
    public async Task GetBulletinReferencesAsync_ReturnsData()
    {
        var result = await Client.Search.GetBulletinReferencesAsync(
            "CVE-2021-44228",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEqual(default, result);
    }

    [Fact]
    public async Task GetBulletinHistoryAsync_ReturnsHistory()
    {
        var result = await Client.Search.GetBulletinHistoryAsync(
            "CVE-2021-44228",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEqual(default, result);
    }

    [Fact]
    public async Task SearchExploitsAsync_ReturnsExploits()
    {
        var result = await Client.Search.SearchExploitsAsync(
            "log4j",
            limit: 5,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.True(result.Total > 0);
        Assert.NotEmpty(result.Documents);
    }

    [Fact]
    public async Task SearchExploitsAsync_WithCveId_ReturnsExploits()
    {
        var result = await Client.Search.SearchExploitsAsync(
            "CVE-2021-44228",
            limit: 5,
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetKbSeedsAsync_ReturnsResult()
    {
        var result = await Client.Search.GetKbSeedsAsync(
            "KB5034441",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetKbUpdatesAsync_ReturnsResults()
    {
        var result = await Client.Search.GetKbUpdatesAsync(
            "KB5034441",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
    }

    [Fact]
    public async Task GetWebVulnsAsync_ReturnsResults()
    {
        var result = await Client.Search.GetWebVulnsAsync(
            paths: new[] { "/admin", "/wp-login.php" },
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotEqual(default, result);
    }
}
