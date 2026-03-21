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
}
