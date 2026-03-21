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
}
