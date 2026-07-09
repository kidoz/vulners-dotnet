namespace VulnersDotNet.Tests;

public class ArchiveServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task DownloadDistributiveAsync_ReturnsZipStream()
    {
        var ct = TestContext.Current.CancellationToken;
        using var stream = await Client.Archive.DownloadDistributiveAsync("debian", "12", ct);

        Assert.NotNull(stream);
        Assert.True(stream.CanRead);

        // Read first bytes to verify it's a ZIP (PK header: 0x50 0x4B)
        var header = new byte[4];
        var bytesRead = await stream.ReadAsync(header, 0, header.Length, ct);
        Assert.True(bytesRead >= 2);
        Assert.Equal(0x50, header[0]); // 'P'
        Assert.Equal(0x4B, header[1]); // 'K'
    }

    [Fact]
    public async Task GetCollectionStateAsync_ReturnsState()
    {
        var state = await Client.Archive.GetCollectionStateAsync(
            "cve",
            TestContext.Current.CancellationToken
        );

        Assert.False(string.IsNullOrEmpty(state.Cursor), "cursor should be populated");
        Assert.True(state.TotalDocs > 0, "total_docs should be positive");
    }

    [Fact]
    public async Task GetCollectionUpdateAsync_DecompressesRecentChanges()
    {
        // Exercises the gzip-decompress path over a small, recent window.
        var after = DateTimeOffset.UtcNow.AddHours(-1);
        var updates = await Client.Archive.GetCollectionUpdateAsync(
            "cve",
            after,
            TestContext.Current.CancellationToken
        );

        // May legitimately be empty in a quiet hour, but the call must succeed and parse.
        Assert.NotNull(updates);
    }

    [Fact]
    public async Task GetFamilyStateAsync_ReturnsState()
    {
        var state = await Client.Archive.GetFamilyStateAsync(
            "unix",
            TestContext.Current.CancellationToken
        );

        Assert.False(string.IsNullOrEmpty(state.Cursor), "cursor should be populated");
        Assert.True(state.TotalDocs > 0, "total_docs should be positive");
    }

    [Fact]
    public async Task GetFamilyUpdateAsync_DecompressesRecentChanges()
    {
        var after = DateTimeOffset.UtcNow.AddHours(-1);
        var updates = await Client.Archive.GetFamilyUpdateAsync(
            "unix",
            after,
            TestContext.Current.CancellationToken
        );

        Assert.NotNull(updates);
    }
}
