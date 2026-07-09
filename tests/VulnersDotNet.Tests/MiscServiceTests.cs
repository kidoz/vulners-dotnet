namespace VulnersDotNet.Tests;

public class MiscServiceTests : IntegrationTestBase
{
    [Fact]
    public async Task GetSuggestionAsync_ReturnsSuggestions()
    {
        var result = await Client.Misc.GetSuggestionAsync(
            "type",
            cancellationToken: TestContext.Current.CancellationToken
        );

        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [Fact]
    public async Task GetApiKeyInfoAsync_ReturnsKeyInfo()
    {
        var info = await Client.Misc.GetApiKeyInfoAsync(TestContext.Current.CancellationToken);

        Assert.NotNull(info);
        Assert.False(string.IsNullOrEmpty(info.LicenseType), "license_type should be populated");
        Assert.True(info.Credit >= 0, "credit should be non-negative");
    }
}
